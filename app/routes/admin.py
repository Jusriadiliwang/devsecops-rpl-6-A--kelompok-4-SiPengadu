"""
Route panel administrator SiPengadu.

Hierarki akses:
- admin (pusat)       : akses penuh — wilayah, admin lokal, log, semua pengaduan, semua user
- admin_kecamatan     : hanya pengaduan di kecamatannya
- admin_desa          : hanya pengaduan di desanya

Semua route dilindungi @admin_required (semua role admin) atau
@superadmin_required (khusus admin pusat).
"""
import bleach
from datetime import datetime
from flask import (
    Blueprint, render_template, redirect, url_for,
    flash, request, abort, jsonify,
)
from flask_login import current_user
from app import db
from app.models import User, Complaint, ActivityLog, ComplaintPhoto, Kecamatan, Desa
from app.forms import (
    AdminResponseForm, AdminEditUserForm,
    KecamatanForm, DesaForm, CreateLocalAdminForm,
)
from app.utils.decorators import admin_required, superadmin_required
from app.utils.logger import log_activity
from app.utils.file_handler import delete_complaint_photo, get_photo_url

admin_bp = Blueprint('admin', __name__)


# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------

def _clean(text: str) -> str:
    if text:
        return bleach.clean(str(text), tags=[], strip=True).strip()
    return ''


def _get_complaint_or_404(cid: int) -> Complaint:
    c = db.session.get(Complaint, cid)
    if c is None:
        abort(404)
    return c


def _get_user_or_404(uid: int) -> User:
    u = db.session.get(User, uid)
    if u is None:
        abort(404)
    return u


def _apply_region_filter(query):
    """
    Terapkan filter wilayah sesuai role admin yang sedang login.
    - admin pusat   : tidak difilter (semua pengaduan)
    - admin_kecamatan : filter kecamatan_id
    - admin_desa      : filter desa_id
    """
    if current_user.role == 'admin_kecamatan':
        query = query.filter(Complaint.kecamatan_id == current_user.kecamatan_id)
    elif current_user.role == 'admin_desa':
        query = query.filter(Complaint.desa_id == current_user.desa_id)
    return query


def _check_complaint_access(c: Complaint) -> bool:
    """Kembalikan True jika admin berhak mengakses pengaduan ini."""
    if current_user.is_superadmin():
        return True
    if current_user.role == 'admin_kecamatan':
        return c.kecamatan_id == current_user.kecamatan_id
    if current_user.role == 'admin_desa':
        return c.desa_id == current_user.desa_id
    return False


def _wilayah_label() -> str:
    """Label wilayah admin yang sedang login untuk judul halaman."""
    if current_user.role == 'admin_kecamatan' and current_user.kecamatan:
        return f'Kecamatan {current_user.kecamatan.name}'
    if current_user.role == 'admin_desa' and current_user.desa:
        return f'Desa {current_user.desa.name}'
    return 'Semua Wilayah'


# ================================================================
# Index / Redirect
# ================================================================

@admin_bp.route('/')
@admin_required
def index():
    return redirect(url_for('admin.dashboard'))


# ================================================================
# Dashboard
# ================================================================

@admin_bp.route('/dashboard')
@admin_required
def dashboard():
    """Dashboard admin: statistik sistem (difilter per wilayah untuk admin lokal)."""
    base_q = _apply_region_filter(Complaint.query)

    total_users      = User.query.filter_by(role='citizen').count()
    total_complaints = base_q.count()
    pending          = base_q.filter_by(status='pending').count()
    in_review        = base_q.filter_by(status='in_review').count()
    resolved         = base_q.filter_by(status='resolved').count()
    rejected         = base_q.filter_by(status='rejected').count()

    recent_complaints = (base_q.order_by(Complaint.created_at.desc()).limit(7).all())

    recent_logs = []
    if current_user.is_superadmin():
        recent_logs = (ActivityLog.query
                       .order_by(ActivityLog.timestamp.desc())
                       .limit(10).all())

    return render_template(
        'admin/dashboard.html',
        title='Dashboard Admin',
        total_users=total_users,
        total_complaints=total_complaints,
        pending=pending, in_review=in_review,
        resolved=resolved, rejected=rejected,
        recent_complaints=recent_complaints,
        recent_logs=recent_logs,
        wilayah_label=_wilayah_label(),
    )


# ================================================================
# Kelola Pengaduan
# ================================================================

@admin_bp.route('/complaints')
@admin_required
def complaints():
    """Daftar pengaduan (difilter per wilayah untuk admin lokal)."""
    page     = request.args.get('page', 1, type=int)
    status   = request.args.get('status', '')
    category = request.args.get('category', '')
    keyword  = request.args.get('q', '').strip()

    query = _apply_region_filter(Complaint.query)
    valid_statuses   = [s[0] for s in Complaint.STATUSES]
    valid_categories = [c[0] for c in Complaint.CATEGORIES]

    if status and status in valid_statuses:
        query = query.filter_by(status=status)
    if category and category in valid_categories:
        query = query.filter_by(category=category)
    if keyword:
        kw = f'%{keyword}%'
        query = query.filter(
            db.or_(Complaint.title.ilike(kw), Complaint.location.ilike(kw))
        )

    pagination = query.order_by(Complaint.created_at.desc()).paginate(
        page=page, per_page=15, error_out=False)

    return render_template(
        'admin/complaints.html',
        title='Kelola Pengaduan',
        pagination=pagination, complaints=pagination.items,
        status=status, category=category, keyword=keyword,
        categories=Complaint.CATEGORIES,
        statuses=Complaint.STATUSES,
        wilayah_label=_wilayah_label(),
    )


@admin_bp.route('/complaints/<int:cid>', methods=['GET', 'POST'])
@admin_required
def complaint_detail(cid):
    """Detail pengaduan dan form respons admin."""
    c = _get_complaint_or_404(cid)

    if not _check_complaint_access(c):
        abort(403)

    form = AdminResponseForm()

    if request.method == 'GET':
        form.status.data         = c.status
        form.admin_response.data = c.admin_response

    if form.validate_on_submit():
        old_status       = c.status
        c.status         = form.status.data
        c.admin_response = _clean(form.admin_response.data)
        c.reviewed_by    = current_user.id
        c.updated_at     = datetime.utcnow()
        db.session.commit()

        log_activity(current_user.id, 'COMPLAINT_STATUS_UPDATED',
                     f'#{c.id} | {old_status} → {c.status} | admin: {current_user.username}')
        flash(f'Status pengaduan #{c.id} berhasil diperbarui.', 'success')
        return redirect(url_for('admin.complaint_detail', cid=cid))

    return render_template(
        'admin/complaint_detail.html',
        title=f'Pengaduan #{c.id}',
        complaint=c, form=form,
        photos=c.photos.order_by(ComplaintPhoto.uploaded_at.asc()).all(),
        photo_urls=[get_photo_url(p.url) for p in c.photos.all()],
    )


@admin_bp.route('/complaints/<int:cid>/delete', methods=['POST'])
@admin_required
def complaint_delete(cid):
    """Hapus pengaduan (aksi admin)."""
    c = _get_complaint_or_404(cid)

    if not _check_complaint_access(c):
        abort(403)

    title = c.title
    for photo in c.photos.all():
        delete_complaint_photo(photo.url, photo.public_id)
    db.session.delete(c)
    db.session.commit()
    log_activity(current_user.id, 'COMPLAINT_DELETED_BY_ADMIN',
                 f'Pengaduan dihapus: {title[:50]}')
    flash('Pengaduan berhasil dihapus.', 'success')
    return redirect(url_for('admin.complaints'))


# ================================================================
# Kelola Pengguna (superadmin only)
# ================================================================

@admin_bp.route('/users')
@superadmin_required
def users():
    """Daftar semua pengguna (citizen + admin lokal)."""
    page   = request.args.get('page', 1, type=int)
    search = request.args.get('q', '').strip()
    role   = request.args.get('role', '')

    query = User.query
    # Exclude current superadmin from bulk list to avoid self-edit accidents
    valid_roles = ['citizen', 'admin_kecamatan', 'admin_desa', 'admin']
    if role and role in valid_roles:
        query = query.filter_by(role=role)
    if search:
        kw = f'%{search}%'
        query = query.filter(
            db.or_(User.username.ilike(kw),
                   User.full_name.ilike(kw),
                   User.email.ilike(kw))
        )

    pagination = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=15, error_out=False)

    return render_template(
        'admin/users.html',
        title='Kelola Pengguna',
        pagination=pagination, users=pagination.items,
        search=search, role_filter=role,
    )


@admin_bp.route('/users/<int:uid>')
@superadmin_required
def user_detail(uid):
    """Detail pengguna dan riwayat pengaduannya."""
    user = _get_user_or_404(uid)
    complaints_list = (user.complaints
                       .order_by(Complaint.created_at.desc())
                       .limit(10).all())

    log_activity(current_user.id, 'ADMIN_VIEW_USER',
                 f'Admin {current_user.username} melihat profil: {user.username}')

    return render_template(
        'admin/user_detail.html',
        title=f'Pengguna: {user.username}',
        user=user, complaints=complaints_list,
    )


@admin_bp.route('/users/<int:uid>/edit', methods=['GET', 'POST'])
@superadmin_required
def user_edit(uid):
    """Edit data pengguna oleh admin."""
    user = _get_user_or_404(uid)
    form = AdminEditUserForm(obj=user)

    if form.validate_on_submit():
        email = _clean(form.email.data).lower()
        conflict = User.query.filter(
            User.email == email, User.id != user.id).first()
        if conflict:
            flash('Email sudah digunakan pengguna lain.', 'danger')
            return render_template('admin/user_edit.html', form=form,
                                   user=user, title='Edit Pengguna')

        old_role   = user.role
        old_active = user.is_active

        user.full_name  = _clean(form.full_name.data)
        user.email      = email
        user.role       = form.role.data
        user.is_active  = form.is_active.data
        user.updated_at = datetime.utcnow()
        db.session.commit()

        if old_role != user.role:
            log_activity(current_user.id, 'USER_ROLE_CHANGED',
                         f'{user.username}: {old_role} → {user.role}')
        if old_active != user.is_active:
            action = 'USER_ACTIVATED' if user.is_active else 'USER_DEACTIVATED'
            log_activity(current_user.id, action,
                         f'Akun {user.username} oleh {current_user.username}')

        flash('Data pengguna berhasil diperbarui.', 'success')
        return redirect(url_for('admin.user_detail', uid=uid))

    return render_template('admin/user_edit.html', form=form,
                           user=user, title='Edit Pengguna')


@admin_bp.route('/users/<int:uid>/toggle', methods=['POST'])
@superadmin_required
def user_toggle(uid):
    """Aktifkan / nonaktifkan akun pengguna."""
    user = _get_user_or_404(uid)

    if user.id == current_user.id:
        flash('Anda tidak dapat menonaktifkan akun sendiri.', 'danger')
        return redirect(url_for('admin.user_detail', uid=uid))

    user.is_active  = not user.is_active
    user.updated_at = datetime.utcnow()
    db.session.commit()

    status_text = 'diaktifkan' if user.is_active else 'dinonaktifkan'
    action      = 'USER_ACTIVATED' if user.is_active else 'USER_DEACTIVATED'
    log_activity(current_user.id, action,
                 f'Akun {user.username} {status_text} oleh {current_user.username}')

    flash(f'Akun {user.username} berhasil {status_text}.', 'success')
    return redirect(url_for('admin.user_detail', uid=uid))


# ================================================================
# Log Aktivitas (superadmin only)
# ================================================================

@admin_bp.route('/logs')
@superadmin_required
def logs():
    """Halaman log aktivitas keamanan — hanya admin pusat."""
    page   = request.args.get('page', 1, type=int)
    action = request.args.get('action', '').strip()

    query = ActivityLog.query
    if action:
        query = query.filter(ActivityLog.action.ilike(f'%{action}%'))

    pagination = query.order_by(ActivityLog.timestamp.desc()).paginate(
        page=page, per_page=20, error_out=False)

    log_activity(current_user.id, 'ADMIN_VIEW_LOGS',
                 f'Admin {current_user.username} mengakses halaman log')

    return render_template(
        'admin/logs.html',
        title='Log Aktivitas',
        pagination=pagination, logs=pagination.items,
        action=action,
    )


# ================================================================
# Kelola Wilayah (superadmin only)
# ================================================================

@admin_bp.route('/regions')
@superadmin_required
def regions():
    """Halaman utama kelola wilayah: daftar kecamatan + desa."""
    kecamatans = Kecamatan.query.order_by(Kecamatan.name).all()
    kec_form   = KecamatanForm(prefix='kec')
    desa_form  = DesaForm(prefix='desa')

    # Isi pilihan kecamatan untuk DesaForm
    desa_form.kecamatan_id.choices = (
        [(0, '-- Pilih Kecamatan --')]
        + [(k.id, k.name) for k in kecamatans]
    )

    return render_template(
        'admin/regions.html',
        title='Kelola Wilayah',
        kecamatans=kecamatans,
        kec_form=kec_form,
        desa_form=desa_form,
    )


@admin_bp.route('/regions/kecamatan/new', methods=['POST'])
@superadmin_required
def kecamatan_create():
    """Tambah kecamatan baru."""
    form = KecamatanForm(prefix='kec')
    if form.validate_on_submit():
        name = _clean(form.name.data)
        if Kecamatan.query.filter_by(name=name).first():
            flash(f'Kecamatan "{name}" sudah ada.', 'warning')
        else:
            k = Kecamatan(name=name, code=_clean(form.code.data) or None)
            db.session.add(k)
            db.session.commit()
            log_activity(current_user.id, 'KECAMATAN_CREATED', f'Kecamatan: {name}')
            flash(f'Kecamatan "{name}" berhasil ditambahkan.', 'success')
    else:
        for field, errors in form.errors.items():
            flash(f'{field}: {", ".join(errors)}', 'danger')
    return redirect(url_for('admin.regions'))


@admin_bp.route('/regions/kecamatan/<int:kid>/edit', methods=['GET', 'POST'])
@superadmin_required
def kecamatan_edit(kid):
    """Edit kecamatan."""
    k = db.session.get(Kecamatan, kid)
    if k is None:
        abort(404)
    form = KecamatanForm(obj=k)
    if form.validate_on_submit():
        name = _clean(form.name.data)
        conflict = Kecamatan.query.filter(
            Kecamatan.name == name, Kecamatan.id != kid).first()
        if conflict:
            flash(f'Nama "{name}" sudah digunakan kecamatan lain.', 'danger')
        else:
            k.name = name
            k.code = _clean(form.code.data) or None
            db.session.commit()
            log_activity(current_user.id, 'KECAMATAN_UPDATED', f'Kecamatan #{kid}: {name}')
            flash('Kecamatan berhasil diperbarui.', 'success')
            return redirect(url_for('admin.regions'))
    return render_template('admin/kecamatan_edit.html', form=form,
                           kecamatan=k, title='Edit Kecamatan')


@admin_bp.route('/regions/kecamatan/<int:kid>/delete', methods=['POST'])
@superadmin_required
def kecamatan_delete(kid):
    """Hapus kecamatan (cascade hapus desa di dalamnya)."""
    k = db.session.get(Kecamatan, kid)
    if k is None:
        abort(404)
    name = k.name
    db.session.delete(k)
    db.session.commit()
    log_activity(current_user.id, 'KECAMATAN_DELETED', f'Kecamatan dihapus: {name}')
    flash(f'Kecamatan "{name}" berhasil dihapus.', 'success')
    return redirect(url_for('admin.regions'))


@admin_bp.route('/regions/desa/new', methods=['POST'])
@superadmin_required
def desa_create():
    """Tambah desa baru."""
    kecamatans = Kecamatan.query.order_by(Kecamatan.name).all()
    form = DesaForm(prefix='desa')
    form.kecamatan_id.choices = (
        [(0, '-- Pilih Kecamatan --')]
        + [(k.id, k.name) for k in kecamatans]
    )
    if form.validate_on_submit() and form.kecamatan_id.data:
        name = _clean(form.name.data)
        kec_id = form.kecamatan_id.data
        exists = Desa.query.filter_by(name=name, kecamatan_id=kec_id).first()
        if exists:
            flash(f'Desa "{name}" sudah ada di kecamatan ini.', 'warning')
        else:
            d = Desa(
                kecamatan_id=kec_id,
                name=name,
                code=_clean(form.code.data) or None,
            )
            db.session.add(d)
            db.session.commit()
            log_activity(current_user.id, 'DESA_CREATED', f'Desa: {name} (kec #{kec_id})')
            flash(f'Desa "{name}" berhasil ditambahkan.', 'success')
    else:
        for field, errors in form.errors.items():
            flash(f'{field}: {", ".join(errors)}', 'danger')
    return redirect(url_for('admin.regions'))


@admin_bp.route('/regions/desa/<int:did>/edit', methods=['GET', 'POST'])
@superadmin_required
def desa_edit(did):
    """Edit desa."""
    d = db.session.get(Desa, did)
    if d is None:
        abort(404)
    kecamatans = Kecamatan.query.order_by(Kecamatan.name).all()
    form = DesaForm(obj=d)
    form.kecamatan_id.choices = [(k.id, k.name) for k in kecamatans]
    if form.validate_on_submit():
        name   = _clean(form.name.data)
        kec_id = form.kecamatan_id.data
        conflict = Desa.query.filter(
            Desa.name == name, Desa.kecamatan_id == kec_id, Desa.id != did).first()
        if conflict:
            flash('Nama desa sudah ada di kecamatan yang sama.', 'danger')
        else:
            d.name         = name
            d.kecamatan_id = kec_id
            d.code         = _clean(form.code.data) or None
            db.session.commit()
            log_activity(current_user.id, 'DESA_UPDATED', f'Desa #{did}: {name}')
            flash('Desa berhasil diperbarui.', 'success')
            return redirect(url_for('admin.regions'))
    return render_template('admin/desa_edit.html', form=form,
                           desa=d, title='Edit Desa')


@admin_bp.route('/regions/desa/<int:did>/delete', methods=['POST'])
@superadmin_required
def desa_delete(did):
    """Hapus desa."""
    d = db.session.get(Desa, did)
    if d is None:
        abort(404)
    name = d.name
    db.session.delete(d)
    db.session.commit()
    log_activity(current_user.id, 'DESA_DELETED', f'Desa dihapus: {name}')
    flash(f'Desa "{name}" berhasil dihapus.', 'success')
    return redirect(url_for('admin.regions'))


# ================================================================
# Kelola Admin Lokal (superadmin only)
# ================================================================

@admin_bp.route('/admin-accounts')
@superadmin_required
def admin_accounts():
    """Daftar akun admin lokal (kecamatan + desa)."""
    admins = (User.query
              .filter(User.role.in_(['admin_kecamatan', 'admin_desa']))
              .order_by(User.created_at.desc())
              .all())
    return render_template(
        'admin/admin_accounts.html',
        title='Akun Admin Lokal',
        admins=admins,
    )


@admin_bp.route('/admin-accounts/new', methods=['GET', 'POST'])
@superadmin_required
def create_admin():
    """Buat akun admin lokal baru."""
    kecamatans = Kecamatan.query.order_by(Kecamatan.name).all()
    all_desas  = Desa.query.order_by(Desa.name).all()

    form = CreateLocalAdminForm()
    form.kecamatan_id.choices = (
        [(0, '-- Pilih Kecamatan --')]
        + [(k.id, k.name) for k in kecamatans]
    )
    form.desa_id.choices = (
        [(0, '-- Pilih Desa --')]
        + [(d.id, f'{d.name} ({d.kecamatan.name})') for d in all_desas]
    )

    if form.validate_on_submit():
        # Validasi unik username / email
        if User.query.filter_by(username=form.username.data).first():
            flash('Username sudah digunakan.', 'danger')
            return render_template('admin/create_admin.html', form=form,
                                   title='Buat Admin Lokal', kecamatans=kecamatans)

        email = _clean(form.email.data).lower()
        if User.query.filter_by(email=email).first():
            flash('Email sudah digunakan.', 'danger')
            return render_template('admin/create_admin.html', form=form,
                                   title='Buat Admin Lokal', kecamatans=kecamatans)

        role     = form.role.data
        kec_id   = form.kecamatan_id.data or None
        desa_id_ = form.desa_id.data or None

        # Validasi konsistensi role vs wilayah
        if role == 'admin_kecamatan' and not kec_id:
            flash('Admin Kecamatan harus memilih kecamatan.', 'danger')
            return render_template('admin/create_admin.html', form=form,
                                   title='Buat Admin Lokal', kecamatans=kecamatans)
        if role == 'admin_desa' and not desa_id_:
            flash('Admin Desa harus memilih desa.', 'danger')
            return render_template('admin/create_admin.html', form=form,
                                   title='Buat Admin Lokal', kecamatans=kecamatans)

        # Jika admin_desa, set kecamatan_id dari desa yang dipilih
        if role == 'admin_desa' and desa_id_:
            desa_obj = db.session.get(Desa, desa_id_)
            if desa_obj:
                kec_id = desa_obj.kecamatan_id

        u = User(
            username     = _clean(form.username.data),
            email        = email,
            full_name    = _clean(form.full_name.data),
            phone        = _clean(form.phone.data),
            role         = role,
            kecamatan_id = kec_id if kec_id else None,
            desa_id      = desa_id_ if desa_id_ else None,
            is_active    = True,
        )
        u.set_password(form.password.data)
        db.session.add(u)
        db.session.commit()

        log_activity(current_user.id, 'ADMIN_ACCOUNT_CREATED',
                     f'Admin lokal dibuat: {u.username} ({role})')
        flash(f'Akun admin "{u.username}" berhasil dibuat.', 'success')
        return redirect(url_for('admin.admin_accounts'))

    return render_template(
        'admin/create_admin.html',
        title='Buat Admin Lokal',
        form=form,
        kecamatans=kecamatans,
    )


# ================================================================
# AJAX: daftar desa untuk kecamatan tertentu
# ================================================================

@admin_bp.route('/api/desas/<int:kecamatan_id>')
@admin_required
def api_desas(kecamatan_id):
    """Kembalikan JSON daftar desa berdasarkan kecamatan_id."""
    desas = (Desa.query
             .filter_by(kecamatan_id=kecamatan_id)
             .order_by(Desa.name)
             .all())
    return jsonify([{'id': d.id, 'name': d.name} for d in desas])
