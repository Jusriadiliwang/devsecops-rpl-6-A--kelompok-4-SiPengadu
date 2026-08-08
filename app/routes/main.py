"""
Route untuk pengguna masyarakat (citizen).

Penerapan secure coding:
1. citizen_required decorator → kontrol akses berbasis peran
2. Filter user_id=current_user.id → mencegah IDOR
3. Validasi status pengaduan → batasan proses bisnis
4. Sanitasi input dengan bleach → cegah XSS
5. Validasi kategori dari whitelist → cegah manipulasi parameter
6. Logging setiap aksi penting
7. Validasi file upload: ekstensi whitelist, ukuran dibatasi config
"""
import os
import bleach
from datetime import datetime
from flask import (
    Blueprint, render_template, redirect, url_for, flash,
    request, session, send_from_directory, current_app, jsonify,
)
from flask_login import current_user, login_required
from app import db
from app.models import Complaint, ComplaintPhoto, Kecamatan, Desa
from app.forms import ComplaintForm, ProfileForm, ChangePasswordForm
from app.utils.decorators import citizen_required
from app.utils.logger import log_activity
from app.utils.file_handler import (
    save_avatar, delete_avatar,
    save_complaint_photo, delete_complaint_photo,
    get_photo_url, MAX_PHOTOS_PER_COMPLAINT,
)

main_bp = Blueprint('main', __name__)


def _clean(text: str) -> str:
    if text:
        return bleach.clean(str(text), tags=[], strip=True).strip()
    return ''


@main_bp.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.is_admin():
            return redirect(url_for('admin.dashboard'))
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))


@main_bp.route('/dashboard')
@citizen_required
def dashboard():
    """Dashboard ringkasan pengaduan citizen."""
    recent = (current_user.complaints
              .order_by(Complaint.created_at.desc())
              .limit(5).all())
    stats = {
        'total':     current_user.complaints.count(),
        'pending':   current_user.complaints.filter_by(status='pending').count(),
        'in_review': current_user.complaints.filter_by(status='in_review').count(),
        'resolved':  current_user.complaints.filter_by(status='resolved').count(),
        'rejected':  current_user.complaints.filter_by(status='rejected').count(),
    }
    return render_template('main/dashboard.html', title='Dashboard',
                           recent=recent, stats=stats)


@main_bp.route('/profile', methods=['GET', 'POST'])
@citizen_required
def profile():
    """Halaman profil pengguna dengan upload avatar."""
    from app.models import User
    form = ProfileForm(obj=current_user)

    if form.validate_on_submit():
        email = _clean(form.email.data).lower()
        conflict = User.query.filter(
            User.email == email,
            User.id != current_user.id,
        ).first()
        if conflict:
            flash('Email sudah digunakan pengguna lain.', 'danger')
            return render_template('main/profile.html', form=form, title='Profil Saya')

        # --- Handle avatar upload ---
        avatar_file = form.avatar.data
        if avatar_file and avatar_file.filename:
            try:
                # Hapus avatar lama jika ada
                if current_user.avatar:
                    delete_avatar(current_user.avatar,
                                  public_id=getattr(current_user, '_avatar_public_id', ''))

                result = save_avatar(avatar_file)
                current_user.avatar = result['url']
                log_activity(current_user.id, 'AVATAR_UPDATED', 'Foto profil diperbarui')
            except ValueError as e:
                flash(str(e), 'danger')
                return render_template('main/profile.html', form=form, title='Profil Saya')

        current_user.full_name  = _clean(form.full_name.data)
        current_user.email      = email
        current_user.phone      = _clean(form.phone.data)
        current_user.address    = _clean(form.address.data)
        current_user.updated_at = datetime.utcnow()
        db.session.commit()

        log_activity(current_user.id, 'PROFILE_UPDATE', 'Profil diperbarui')
        flash('Profil berhasil diperbarui.', 'success')
        return redirect(url_for('main.profile'))

    return render_template('main/profile.html', form=form, title='Profil Saya')


@main_bp.route('/profile/password', methods=['GET', 'POST'])
@citizen_required
def change_password():
    """Ubah password pengguna."""
    form = ChangePasswordForm()

    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            log_activity(current_user.id, 'PASSWORD_CHANGE_FAILED',
                         'Password lama tidak cocok')
            flash('Password saat ini tidak benar.', 'danger')
            return render_template('main/change_password.html', form=form,
                                   title='Ubah Password')

        current_user.set_password(form.new_password.data)
        current_user.updated_at = datetime.utcnow()
        db.session.commit()

        # ----------------------------------------------------------------
        # FIX #3: Perbarui session fingerprint sesi SAAT INI agar pengguna
        # tidak ter-logout dari perangkat yang sedang digunakan.
        # ----------------------------------------------------------------
        session['_pf'] = current_user.password_hash[-10:]

        log_activity(current_user.id, 'PASSWORD_CHANGED', 'Password berhasil diubah')
        flash('Password berhasil diubah.', 'success')
        return redirect(url_for('main.profile'))

    return render_template('main/change_password.html', form=form, title='Ubah Password')


@main_bp.route('/complaints')
@citizen_required
def complaints():
    """Daftar pengaduan milik pengguna yang sedang login."""
    page   = request.args.get('page', 1, type=int)
    status = request.args.get('status', '')

    # ----------------------------------------------------------------
    # KEAMANAN: Filter user_id=current_user.id mencegah IDOR
    # ----------------------------------------------------------------
    query = current_user.complaints
    valid_statuses = ['pending', 'in_review', 'resolved', 'rejected']
    if status in valid_statuses:
        query = query.filter_by(status=status)

    pagination = query.order_by(Complaint.created_at.desc()).paginate(
        page=page, per_page=10, error_out=False)

    return render_template('main/complaints.html', title='Pengaduan Saya',
                           pagination=pagination, complaints=pagination.items,
                           status=status)


def _populate_wilayah_choices(form):
    """Isi pilihan kecamatan dan desa pada ComplaintForm."""
    kecamatans = Kecamatan.query.order_by(Kecamatan.name).all()
    all_desas  = Desa.query.order_by(Desa.name).all()
    form.kecamatan_id.choices = (
        [(0, '-- Pilih Kecamatan (opsional) --')]
        + [(k.id, k.name) for k in kecamatans]
    )
    form.desa_id.choices = (
        [(0, '-- Pilih Desa/Kelurahan (opsional) --')]
        + [(d.id, d.name) for d in all_desas]
    )


@main_bp.route('/complaints/new', methods=['GET', 'POST'])
@citizen_required
def complaint_new():
    """Buat pengaduan baru dengan opsional upload foto bukti (maks 5)."""
    form = ComplaintForm()
    _populate_wilayah_choices(form)
    valid_categories = [c[0] for c in Complaint.CATEGORIES]

    if form.validate_on_submit():
        if form.category.data not in valid_categories:
            flash('Kategori tidak valid.', 'danger')
            return render_template('main/complaint_new.html', form=form,
                                   title='Buat Pengaduan')

        kec_id  = form.kecamatan_id.data if form.kecamatan_id.data else None
        desa_id = form.desa_id.data      if form.desa_id.data      else None
        # Coerce 0 → None
        if kec_id == 0:
            kec_id = None
        if desa_id == 0:
            desa_id = None

        c = Complaint(
            user_id      = current_user.id,
            title        = _clean(form.title.data),
            category     = form.category.data,
            location     = _clean(form.location.data),
            description  = _clean(form.description.data),
            status       = 'pending',
            kecamatan_id = kec_id,
            desa_id      = desa_id,
        )
        db.session.add(c)
        db.session.flush()  # dapat c.id sebelum commit

        # --- Handle foto bukti ---
        photo_files = request.files.getlist('photos')
        photo_files = [f for f in photo_files if f and f.filename]
        uploaded_count = 0
        photo_errors = []

        for pf in photo_files[:MAX_PHOTOS_PER_COMPLAINT]:
            try:
                result = save_complaint_photo(pf)
                photo = ComplaintPhoto(
                    complaint_id = c.id,
                    url          = result['url'],
                    public_id    = result.get('public_id', ''),
                    filename     = result.get('filename', ''),
                )
                db.session.add(photo)
                uploaded_count += 1
            except (ValueError, Exception) as e:
                photo_errors.append(str(e))

        db.session.commit()

        if photo_errors:
            flash(f'Pengaduan terkirim, namun {len(photo_errors)} foto gagal diupload: '
                  f'{photo_errors[0]}', 'warning')
        else:
            flash('Pengaduan berhasil dikirim. Tim kami akan segera meninjau.', 'success')

        log_activity(current_user.id, 'COMPLAINT_CREATED',
                     f'Pengaduan #{c.id}: {c.title[:50]} ({uploaded_count} foto)')
        return redirect(url_for('main.complaints'))

    return render_template('main/complaint_new.html', form=form, title='Buat Pengaduan')


@main_bp.route('/complaints/<int:cid>')
@citizen_required
def complaint_detail(cid):
    """Detail pengaduan — hanya milik pengguna sendiri."""
    # ----------------------------------------------------------------
    # KEAMANAN: Verifikasi kepemilikan sebelum menampilkan data (IDOR)
    # ----------------------------------------------------------------
    c = Complaint.query.filter_by(id=cid, user_id=current_user.id).first_or_404()
    photos = c.photos.order_by(ComplaintPhoto.uploaded_at.asc()).all()
    photo_urls = [get_photo_url(p.url) for p in photos]
    return render_template('main/complaint_detail.html',
                           title=f'Pengaduan #{c.id}', complaint=c,
                           photos=photos, photo_urls=photo_urls)


@main_bp.route('/complaints/<int:cid>/edit', methods=['GET', 'POST'])
@citizen_required
def complaint_edit(cid):
    """Edit pengaduan — hanya jika masih 'pending'."""
    c = Complaint.query.filter_by(id=cid, user_id=current_user.id).first_or_404()

    if c.status != 'pending':
        flash('Pengaduan yang sudah diproses tidak dapat diedit.', 'warning')
        return redirect(url_for('main.complaint_detail', cid=cid))

    form = ComplaintForm(obj=c)
    _populate_wilayah_choices(form)
    valid_categories = [x[0] for x in Complaint.CATEGORIES]

    if form.validate_on_submit():
        if form.category.data not in valid_categories:
            flash('Kategori tidak valid.', 'danger')
            return render_template('main/complaint_edit.html', form=form,
                                   complaint=c, title='Edit Pengaduan')

        old_title = c.title
        c.title       = _clean(form.title.data)
        c.category    = form.category.data
        c.location    = _clean(form.location.data)
        c.description = _clean(form.description.data)
        c.updated_at  = datetime.utcnow()

        # --- Handle tambah foto baru saat edit ---
        photo_files = request.files.getlist('photos')
        photo_files = [f for f in photo_files if f and f.filename]
        existing_count = c.photos.count()
        slots_left = MAX_PHOTOS_PER_COMPLAINT - existing_count

        for pf in photo_files[:slots_left]:
            try:
                result = save_complaint_photo(pf)
                photo = ComplaintPhoto(
                    complaint_id = c.id,
                    url          = result['url'],
                    public_id    = result.get('public_id', ''),
                    filename     = result.get('filename', ''),
                )
                db.session.add(photo)
            except Exception:
                pass

        db.session.commit()

        log_activity(current_user.id, 'COMPLAINT_EDITED',
                     f'#{c.id} diedit. Judul lama: {old_title[:40]}')
        flash('Pengaduan berhasil diperbarui.', 'success')
        return redirect(url_for('main.complaint_detail', cid=cid))

    photos = c.photos.order_by(ComplaintPhoto.uploaded_at.asc()).all()
    return render_template('main/complaint_edit.html', form=form,
                           complaint=c, photos=photos, title='Edit Pengaduan')


@main_bp.route('/complaints/<int:cid>/photos/<int:pid>/delete', methods=['POST'])
@citizen_required
def complaint_photo_delete(cid, pid):
    """Hapus satu foto dari pengaduan (hanya pending)."""
    c = Complaint.query.filter_by(id=cid, user_id=current_user.id).first_or_404()
    if c.status != 'pending':
        flash('Foto tidak dapat dihapus karena pengaduan sudah diproses.', 'warning')
        return redirect(url_for('main.complaint_detail', cid=cid))

    photo = ComplaintPhoto.query.filter_by(id=pid, complaint_id=cid).first_or_404()
    delete_complaint_photo(photo.url, photo.public_id)
    db.session.delete(photo)
    db.session.commit()
    flash('Foto berhasil dihapus.', 'success')
    return redirect(url_for('main.complaint_edit', cid=cid))


@main_bp.route('/complaints/<int:cid>/delete', methods=['POST'])
@citizen_required
def complaint_delete(cid):
    """Hapus pengaduan — hanya jika masih 'pending'."""
    c = Complaint.query.filter_by(id=cid, user_id=current_user.id).first_or_404()

    if c.status != 'pending':
        flash('Pengaduan yang sudah diproses tidak dapat dihapus.', 'warning')
        return redirect(url_for('main.complaints'))

    # Hapus semua foto terkait dari storage
    for photo in c.photos.all():
        delete_complaint_photo(photo.url, photo.public_id)

    title = c.title
    db.session.delete(c)
    db.session.commit()

    log_activity(current_user.id, 'COMPLAINT_DELETED',
                 f'Pengaduan dihapus: {title[:50]}')
    flash('Pengaduan berhasil dihapus.', 'success')
    return redirect(url_for('main.complaints'))


@main_bp.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    """
    Serve file upload lokal (development only).
    Di production (Vercel + Cloudinary) route ini tidak digunakan karena
    foto disimpan di Cloudinary dan URL-nya adalah URL absolut.
    """
    upload_folder = current_app.config['UPLOAD_FOLDER']
    directory = os.path.dirname(os.path.join(upload_folder, filename))
    base = os.path.basename(filename)
    return send_from_directory(directory, base)


# ================================================================
# AJAX: daftar desa untuk kecamatan tertentu (public read)
# ================================================================

@main_bp.route('/api/desas/<int:kecamatan_id>')
def api_desas(kecamatan_id):
    """JSON list desa berdasarkan kecamatan_id — dipakai oleh ComplaintForm JS."""
    desas = (Desa.query
             .filter_by(kecamatan_id=kecamatan_id)
             .order_by(Desa.name)
             .all())
    return jsonify([{'id': d.id, 'name': d.name} for d in desas])
