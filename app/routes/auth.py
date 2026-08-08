"""
Route autentikasi: login, register, logout.

Penerapan secure coding:
1. ORM (bukan raw SQL) → mencegah SQL Injection
2. bcrypt hash → password aman
3. Pesan error generik → cegah user enumeration
4. CSRF token pada setiap form → cegah CSRF Attack
5. Open redirect prevention (urlparse) pada parameter ?next=
6. Security logging untuk setiap event autentikasi
7. Rate limiting 5 percobaan/menit pada login → cegah brute force
8. Session fingerprint → invalidasi session lain saat password berubah
"""
import bleach
from urllib.parse import urlparse
from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from app import db, limiter
from app.models import User
from app.forms import LoginForm, RegisterForm
from app.utils.logger import log_activity

auth_bp = Blueprint('auth', __name__)


def _clean(text: str) -> str:
    """Hapus tag HTML dari input teks (sanitasi)."""
    if text:
        return bleach.clean(str(text), tags=[], strip=True).strip()
    return ''


def _safe_next(next_url: str) -> str:
    """
    Validasi parameter ?next= untuk mencegah open redirect.

    FIX: Menggunakan urlparse untuk memastikan URL tidak memiliki
    netloc (domain) atau scheme (http://) — hanya path relatif yang aman.
    Validasi sebelumnya (startswith('/') + not startswith('//'))
    masih bisa di-bypass dengan URL-encoded characters.
    """
    if not next_url:
        return ''
    try:
        parsed = urlparse(next_url)
        # Hanya izinkan path relatif: tidak boleh ada netloc atau scheme
        if parsed.netloc or parsed.scheme:
            return ''
        # Path harus diawali '/' dan tidak boleh mengandung sekuens berbahaya
        if parsed.path and parsed.path.startswith('/') and not parsed.path.startswith('//'):
            return next_url
    except Exception:
        pass
    return ''


@auth_bp.route('/login', methods=['GET', 'POST'])
# ----------------------------------------------------------------
# FIX #2: Rate Limiter — maksimal 5 percobaan login per menit per IP
# Mencegah brute force attack (OWASP A07:2021).
# Error 429 dikembalikan jika batas terlampaui.
# ----------------------------------------------------------------
@limiter.limit("5 per minute", error_message="Terlalu banyak percobaan login. Coba lagi dalam 1 menit.")
def login():
    """Halaman login."""
    if current_user.is_authenticated:
        if current_user.is_admin():
            return redirect(url_for('admin.dashboard'))
        return redirect(url_for('main.dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        username = _clean(form.username.data)

        # ----------------------------------------------------------------
        # AMAN: Gunakan ORM — parameterized query otomatis
        # RAWAN: db.engine.execute(f"SELECT * FROM users WHERE username='{username}'")
        # ----------------------------------------------------------------
        user = User.query.filter_by(username=username).first()

        if user and user.is_active and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            session.permanent = True

            # ----------------------------------------------------------------
            # FIX #3: Simpan session fingerprint berdasarkan hash password.
            # Ketika password diubah, hash baru → fingerprint baru → session
            # di perangkat lain otomatis tidak valid saat load_user dipanggil.
            # ----------------------------------------------------------------
            session['_pf'] = user.password_hash[-10:]

            log_activity(
                user_id=user.id,
                action='LOGIN_SUCCESS',
                details=f'Username: {username}',
            )

            flash(f'Selamat datang, {user.full_name}!', 'success')

            next_page = _safe_next(request.args.get('next', ''))
            if next_page:
                return redirect(next_page)

            return redirect(url_for('admin.dashboard') if user.is_admin()
                            else url_for('main.dashboard'))

        # ----------------------------------------------------------------
        # KEAMANAN: Pesan error GENERIK — tidak memberi tahu apakah
        # username atau password yang salah (cegah user enumeration)
        # ----------------------------------------------------------------
        log_activity(
            user_id=None,
            action='LOGIN_FAILED',
            details=f'Percobaan login dengan username: {username}',
        )
        flash('Username atau password salah.', 'danger')

    return render_template('auth/login.html', form=form, title='Masuk')


@auth_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def register():
    """Halaman registrasi pengguna baru."""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = RegisterForm()
    if form.validate_on_submit():
        username  = _clean(form.username.data)
        email     = _clean(form.email.data).lower()
        full_name = _clean(form.full_name.data)
        phone     = _clean(form.phone.data)
        address   = _clean(form.address.data)

        # Cek duplikasi username / email melalui ORM
        if User.query.filter_by(username=username).first():
            flash('Username sudah digunakan. Pilih username lain.', 'danger')
            return render_template('auth/register.html', form=form, title='Daftar')

        if User.query.filter_by(email=email).first():
            flash('Email sudah terdaftar.', 'danger')
            return render_template('auth/register.html', form=form, title='Daftar')

        user = User(
            username=username,
            email=email,
            full_name=full_name,
            phone=phone,
            address=address,
            role='citizen',
        )
        # set_password() melakukan hashing bcrypt — BUKAN plaintext
        user.set_password(form.password.data)

        db.session.add(user)
        db.session.commit()

        log_activity(
            user_id=user.id,
            action='REGISTER',
            details=f'Akun baru: {username}',
        )

        flash('Registrasi berhasil! Silakan login.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html', form=form, title='Daftar')


@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """Logout dan hapus session."""
    log_activity(
        user_id=current_user.id,
        action='LOGOUT',
        details=f'Username: {current_user.username}',
    )
    logout_user()
    session.clear()
    flash('Anda telah berhasil keluar.', 'info')
    return redirect(url_for('auth.login'))
