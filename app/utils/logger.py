"""
Modul logging aktivitas keamanan SiPengadu.

Aktivitas yang WAJIB dicatat (Security Logging):
- LOGIN_SUCCESS              : login berhasil
- LOGIN_FAILED               : login gagal
- LOGOUT                     : pengguna keluar
- REGISTER                   : registrasi akun baru
- PROFILE_UPDATE             : pembaruan profil
- PASSWORD_CHANGED           : password berhasil diubah
- PASSWORD_CHANGE_FAILED     : percobaan ubah password gagal
- COMPLAINT_CREATED          : pengaduan dibuat
- COMPLAINT_EDITED           : pengaduan diedit
- COMPLAINT_DELETED          : pengaduan dihapus
- COMPLAINT_STATUS_UPDATED   : status pengaduan diperbarui admin
- USER_ROLE_CHANGED          : peran pengguna diubah admin
- USER_ACTIVATED             : akun diaktifkan
- USER_DEACTIVATED           : akun dinonaktifkan
- ACCESS_DENIED              : percobaan akses ditolak (non-admin)
- ACCESS_DENIED_INACTIVE     : akun citizen nonaktif mencoba akses
- ACCESS_DENIED_INACTIVE_ADMIN: akun admin nonaktif mencoba akses
- ADMIN_VIEW_USER            : admin melihat profil pengguna
- ADMIN_VIEW_LOGS            : admin mengakses halaman log
"""
from datetime import datetime, timezone
from flask import request


def log_activity(user_id, action: str, details: str = None) -> None:
    """
    Catat aktivitas keamanan ke tabel activity_logs.

    FIX #5: IP address diambil via request.remote_addr yang sudah
    diproses oleh ProxyFix middleware — tidak perlu parsing manual
    X-Forwarded-For yang bisa di-spoof oleh client.

    FIX MEDIUM: Gunakan datetime.now(timezone.utc) — datetime.utcnow()
    deprecated sejak Python 3.12.

    Parameter:
        user_id : ID pengguna (None jika belum autentikasi)
        action  : Kode aksi (contoh: 'LOGIN_SUCCESS')
        details : Keterangan tambahan, dipotong maksimal 500 karakter
    """
    from app import db
    from app.models import ActivityLog

    try:
        # ProxyFix sudah memvalidasi X-Forwarded-For sesuai konfigurasi
        # x_for=1 di __init__.py — request.remote_addr sudah aman
        ip = (request.remote_addr or 'unknown')[:45]
        ua = (request.user_agent.string or '')[:255] if request else ''

        # Truncate details agar tidak membebani storage database
        safe_details = (str(details)[:500]) if details else None

        entry = ActivityLog(
            user_id=user_id,
            action=action,
            details=safe_details,
            ip_address=ip,
            user_agent=ua,
            timestamp=datetime.now(timezone.utc).replace(tzinfo=None),
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        # Logging TIDAK boleh menghentikan alur utama aplikasi
        try:
            db.session.rollback()
        except Exception:
            pass
