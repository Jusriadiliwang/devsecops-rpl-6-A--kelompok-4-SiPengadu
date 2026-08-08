"""
Utilitas upload file untuk SiPengadu.

Strategi:
- Jika env var CLOUDINARY_URL di-set → upload ke Cloudinary (wajib di Vercel/production
  karena filesystem-nya ephemeral).
- Jika tidak → simpan lokal di UPLOAD_FOLDER (cukup untuk development).

Keamanan:
- Validasi ekstensi file secara server-side (whitelist).
- Nama file di-generate ulang dengan UUID untuk mencegah path traversal.
- Ukuran file dibatasi via MAX_CONTENT_LENGTH di config.
"""
import os
import uuid
from flask import current_app
from werkzeug.utils import secure_filename

ALLOWED_IMAGE_EXT = {'png', 'jpg', 'jpeg', 'webp', 'gif'}
MAX_PHOTOS_PER_COMPLAINT = 5


def _allowed_image(filename: str) -> bool:
    """Cek apakah ekstensi file ada dalam whitelist gambar."""
    return (
        '.' in filename and
        filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXT
    )


def _use_cloudinary() -> bool:
    """Kembalikan True jika CLOUDINARY_URL tersedia."""
    return bool(os.environ.get('CLOUDINARY_URL'))


# ================================================================
# Cloudinary helpers
# ================================================================

def _cloudinary_upload(file_storage, folder: str) -> dict:
    """
    Upload FileStorage ke Cloudinary.
    Kembalikan dict {'url': str, 'public_id': str}.
    """
    import cloudinary.uploader  # type: ignore
    result = cloudinary.uploader.upload(
        file_storage,
        folder=folder,
        resource_type='image',
        allowed_formats=['jpg', 'jpeg', 'png', 'webp', 'gif'],
    )
    return {
        'url': result.get('secure_url', result.get('url', '')),
        'public_id': result.get('public_id', ''),
        'filename': '',
    }


def _cloudinary_delete(public_id: str) -> None:
    """Hapus aset dari Cloudinary berdasarkan public_id."""
    if not public_id:
        return
    try:
        import cloudinary.uploader  # type: ignore
        cloudinary.uploader.destroy(public_id)
    except Exception:
        pass


# ================================================================
# Local helpers
# ================================================================

def _local_upload(file_storage, subfolder: str) -> dict:
    """
    Simpan FileStorage ke folder lokal.
    Kembalikan dict {'url': str_path_relatif, 'public_id': '', 'filename': str}.
    """
    ext = file_storage.filename.rsplit('.', 1)[1].lower()
    unique_name = f"{uuid.uuid4().hex}.{ext}"
    save_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], subfolder)
    os.makedirs(save_dir, exist_ok=True)
    save_path = os.path.join(save_dir, unique_name)
    file_storage.save(save_path)
    # Kembalikan path relatif yang bisa dipakai di url_for('main.uploaded_file')
    rel_path = f"{subfolder}/{unique_name}"
    return {
        'url': rel_path,      # path relatif, bukan URL absolut
        'public_id': '',
        'filename': unique_name,
    }


def _local_delete(rel_path: str) -> None:
    """Hapus file lokal berdasarkan path relatif."""
    if not rel_path:
        return
    try:
        full = os.path.join(current_app.config['UPLOAD_FOLDER'], rel_path)
        if os.path.isfile(full):
            os.remove(full)
    except Exception:
        pass


# ================================================================
# Public API
# ================================================================

def save_avatar(file_storage) -> dict:
    """
    Upload foto profil (avatar).
    Kembalikan dict {'url', 'public_id', 'filename'} atau raise ValueError jika gagal.
    """
    if not file_storage or not file_storage.filename:
        raise ValueError('File tidak boleh kosong.')
    if not _allowed_image(file_storage.filename):
        raise ValueError('Format file tidak didukung. Gunakan JPG, PNG, atau WEBP.')

    if _use_cloudinary():
        return _cloudinary_upload(file_storage, folder='sipengadu/avatars')
    else:
        return _local_upload(file_storage, subfolder='avatars')


def delete_avatar(url: str, public_id: str = '') -> None:
    """Hapus foto profil lama."""
    if _use_cloudinary():
        _cloudinary_delete(public_id)
    else:
        _local_delete(url)


def save_complaint_photo(file_storage) -> dict:
    """
    Upload satu foto bukti pengaduan.
    Kembalikan dict {'url', 'public_id', 'filename'} atau raise ValueError jika gagal.
    """
    if not file_storage or not file_storage.filename:
        raise ValueError('File tidak boleh kosong.')
    if not _allowed_image(file_storage.filename):
        raise ValueError('Format file tidak didukung. Gunakan JPG, PNG, atau WEBP.')

    if _use_cloudinary():
        return _cloudinary_upload(file_storage, folder='sipengadu/complaints')
    else:
        return _local_upload(file_storage, subfolder='complaints')


def delete_complaint_photo(url: str, public_id: str = '') -> None:
    """Hapus foto pengaduan."""
    if _use_cloudinary():
        _cloudinary_delete(public_id)
    else:
        _local_delete(url)


def get_photo_url(url_or_path: str) -> str:
    """
    Kembalikan URL yang bisa dipakai di template <img src="...">.
    - Jika sudah berupa URL absolut (Cloudinary) → kembalikan apa adanya.
    - Jika path lokal relatif → kembalikan route /uploads/<path>.
    """
    if not url_or_path:
        return ''
    if url_or_path.startswith('http://') or url_or_path.startswith('https://'):
        return url_or_path
    # path lokal → pakai route main.uploaded_file
    from flask import url_for
    return url_for('main.uploaded_file', filename=url_or_path)
