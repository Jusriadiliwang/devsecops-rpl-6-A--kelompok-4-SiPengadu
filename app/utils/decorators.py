"""
Decorator untuk kontrol akses berbasis peran (RBAC).

Penerapan prinsip Least Privilege:
- admin_required      : semua role admin (admin, admin_kecamatan, admin_desa) yang is_active=True
- superadmin_required : hanya admin pusat (role='admin') yang is_active=True
- citizen_required    : hanya pengguna dengan role='citizen' DAN is_active=True

Kegagalan otorisasi dicatat sebagai log keamanan dan
mengembalikan HTTP 403 Forbidden — TIDAK menampilkan
informasi sensitif sistem (OWASP A01:2021).
"""
from functools import wraps
from flask import abort, redirect, url_for, request, session
from flask_login import current_user, logout_user
from app.utils.logger import log_activity


def _kick_inactive(user):
    """Keluarkan user nonaktif dan bersihkan session."""
    log_activity(
        user_id=user.id,
        action='ACCESS_DENIED_INACTIVE',
        details=(
            f'Akun nonaktif {user.username} '
            f'mencoba akses: {request.path} — sesi dihapus'
        ),
    )
    logout_user()
    session.clear()
    abort(403)


def admin_required(f):
    """
    Decorator: route dapat diakses oleh SEMUA role admin yang aktif.
    (admin pusat, admin_kecamatan, admin_desa)

    FIX KRITIS: Cek is_active — admin yang di-suspend harus
    langsung dikeluarkan meskipun session masih ada.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))

        if not current_user.is_admin():
            log_activity(
                user_id=current_user.id,
                action='ACCESS_DENIED',
                details=(
                    f'Non-admin {current_user.username} '
                    f'mencoba akses: {request.path}'
                ),
            )
            abort(403)

        if not current_user.is_active:
            _kick_inactive(current_user)

        return f(*args, **kwargs)
    return decorated


def superadmin_required(f):
    """
    Decorator: route HANYA untuk admin pusat (role='admin') yang aktif.
    Digunakan pada: log aktivitas, kelola wilayah, buat admin lokal.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))

        if not current_user.is_superadmin():
            log_activity(
                user_id=current_user.id,
                action='ACCESS_DENIED_SUPERADMIN',
                details=(
                    f'{current_user.username} (role={current_user.role}) '
                    f'mencoba akses superadmin: {request.path}'
                ),
            )
            abort(403)

        if not current_user.is_active:
            _kick_inactive(current_user)

        return f(*args, **kwargs)
    return decorated


def citizen_required(f):
    """Decorator: route hanya untuk citizen aktif (semua admin diarahkan ke panel admin)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))
        if current_user.is_admin():
            return redirect(url_for('admin.dashboard'))
        if not current_user.is_active:
            _kick_inactive(current_user)
        return f(*args, **kwargs)
    return decorated
