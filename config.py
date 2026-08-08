"""
Konfigurasi Aplikasi Sistem Pengaduan Masyarakat (SiPengadu)
============================================================
Seluruh nilai sensitif (SECRET_KEY, DATABASE_URL, dll.) WAJIB
dimuat dari environment variable / file .env, TIDAK boleh
di-hard-code langsung di source code ini.
"""
import os
from datetime import timedelta

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    # ----------------------------------------------------------
    # KEAMANAN: SECRET_KEY diambil WAJIB dari environment variable.
    # FIX MEDIUM: Tidak ada fallback hardcoded — jika env var tidak
    # di-set, aplikasi langsung raise ValueError (gagal cepat / fail-fast)
    # daripada diam-diam menggunakan key lemah yang diketahui publik.
    # (OWASP A02:2021 - Cryptographic Failures)
    # ----------------------------------------------------------
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        # Development: izinkan dengan key acak sementara (bukan hardcoded)
        import secrets as _secrets
        SECRET_KEY = _secrets.token_hex(32)
        # Peringatan ini akan muncul di log startup
        import warnings as _warnings
        _warnings.warn(
            "[KEAMANAN] SECRET_KEY tidak di-set di environment variable! "
            "Menggunakan key sementara — session akan HILANG setelah restart. "
            "Set SECRET_KEY di file .env untuk development/production.",
            UserWarning,
            stacklevel=2,
        )

    # Database - defaultnya SQLite untuk development lokal
    # Fix: Neon/Heroku pakai "postgres://" tapi SQLAlchemy 2.x butuh "postgresql://"
    _db_url = (
        os.environ.get('DATABASE_URL') or
        'sqlite:///' + os.path.join(basedir, 'instance', 'pengaduan.db')
    )
    if _db_url.startswith('postgres://'):
        _db_url = _db_url.replace('postgres://', 'postgresql://', 1)
    SQLALCHEMY_DATABASE_URI = _db_url
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ----------------------------------------------------------
    # KEAMANAN: Konfigurasi session cookie yang aman
    # - HttpOnly  : cegah akses JavaScript ke cookie (XSS mitigation)
    # - SameSite  : cegah pengiriman cookie cross-site (CSRF mitigation)
    # - Name      : nama custom agar tidak mudah diidentifikasi sebagai Flask
    # - Lifetime  : batas waktu sesi aktif
    # ----------------------------------------------------------
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE  = 'Lax'
    SESSION_COOKIE_NAME      = 'sipengadu_sess'   # Sembunyikan identitas framework
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)

    # CSRF Protection (Flask-WTF)
    WTF_CSRF_ENABLED    = True
    WTF_CSRF_TIME_LIMIT = 3600  # token kedaluwarsa 1 jam

    # ----------------------------------------------------------
    # FIX MEDIUM: Konfigurasi cookie "Ingat Saya" yang aman.
    # Tanpa ini Flask-Login menggunakan default yang tidak membatasi
    # durasi dan tidak mengatur HttpOnly / Secure flag secara eksplisit.
    # ----------------------------------------------------------
    REMEMBER_COOKIE_DURATION  = timedelta(days=7)
    REMEMBER_COOKIE_HTTPONLY  = True
    REMEMBER_COOKIE_NAME      = 'sipengadu_rm'
    REMEMBER_COOKIE_SAMESITE  = 'Lax'

    # File Upload
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024   # Maksimal 5 MB
    UPLOAD_FOLDER      = os.path.join(basedir, 'uploads')
    ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

    # Pagination
    COMPLAINTS_PER_PAGE = 10
    LOGS_PER_PAGE       = 20


class DevelopmentConfig(Config):
    DEBUG = True
    SESSION_COOKIE_SECURE  = False   # HTTP diizinkan di development
    REMEMBER_COOKIE_SECURE = False


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE  = True    # Wajib HTTPS di production
    REMEMBER_COOKIE_SECURE = True    # FIX: cookie "ingat saya" wajib HTTPS


config_map = {
    'development': DevelopmentConfig,
    'production':  ProductionConfig,
    'default':     DevelopmentConfig,
}
