"""
Konfigurasi Aplikasi Sistem Pengaduan Masyarakat (SiPengadu)
============================================================
Seluruh nilai sensitif (SECRET_KEY, DATABASE_URL, dll.) WAJIB
dimuat dari environment variable / file .env, TIDAK boleh
di-hard-code langsung di source code ini.
"""
import os
from datetime import timedelta
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

basedir = os.path.abspath(os.path.dirname(__file__))


def _build_db_uri():
    """
    Bangun DATABASE URI yang kompatibel dengan pg8000 (pure-Python driver).
    - Konversi scheme postgres:// / postgresql:// → postgresql+pg8000://
    - Hapus query param yang tidak dikenal pg8000 (sslmode, channel_binding)
    - Tambahkan ssl_context=True untuk koneksi aman ke Neon
    """
    raw = (
        os.environ.get('DATABASE_URL')
        or 'sqlite:///' + os.path.join(basedir, 'instance', 'pengaduan.db')
    )

    if raw.startswith('sqlite'):
        return raw, {'pool_pre_ping': True}

    # Normalisasi scheme ke postgresql+pg8000://
    if raw.startswith('postgres://'):
        raw = 'postgresql+pg8000://' + raw[len('postgres://'):]
    elif raw.startswith('postgresql://') and '+' not in raw.split('://')[0]:
        raw = 'postgresql+pg8000://' + raw[len('postgresql://'):]

    # Hapus query param yang tidak didukung pg8000
    parsed = urlparse(raw)
    params = parse_qs(parsed.query, keep_blank_values=True)
    for bad_param in ('sslmode', 'channel_binding', 'options'):
        params.pop(bad_param, None)
    new_query = urlencode({k: v[0] for k, v in params.items()})
    clean_url = urlunparse(parsed._replace(query=new_query))

    # Engine options untuk Vercel serverless + Neon
    engine_opts = {
        'pool_pre_ping': True,
        'pool_size': 1,
        'max_overflow': 0,
        'pool_timeout': 30,
        'connect_args': {'ssl_context': True},
    }
    return clean_url, engine_opts


_DB_URI, _ENGINE_OPTIONS = _build_db_uri()


class Config:
    # ----------------------------------------------------------
    # KEAMANAN: SECRET_KEY diambil WAJIB dari environment variable.
    # ----------------------------------------------------------
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        import secrets as _secrets
        SECRET_KEY = _secrets.token_hex(32)
        import warnings as _warnings
        _warnings.warn(
            "[KEAMANAN] SECRET_KEY tidak di-set di environment variable! "
            "Menggunakan key sementara — session akan HILANG setelah restart. "
            "Set SECRET_KEY di file .env untuk development/production.",
            UserWarning,
            stacklevel=2,
        )

    # Database
    SQLALCHEMY_DATABASE_URI = _DB_URI
    SQLALCHEMY_ENGINE_OPTIONS = _ENGINE_OPTIONS
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ----------------------------------------------------------
    # KEAMANAN: Konfigurasi session cookie yang aman
    # ----------------------------------------------------------
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE  = 'Lax'
    SESSION_COOKIE_NAME      = 'sipengadu_sess'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)

    # CSRF Protection (Flask-WTF)
    WTF_CSRF_ENABLED    = True
    WTF_CSRF_TIME_LIMIT = 3600

    # Cookie "Ingat Saya"
    REMEMBER_COOKIE_DURATION  = timedelta(days=7)
    REMEMBER_COOKIE_HTTPONLY  = True
    REMEMBER_COOKIE_NAME      = 'sipengadu_rm'
    REMEMBER_COOKIE_SAMESITE  = 'Lax'

    # File Upload — gunakan /tmp di production (Vercel read-only fs)
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024
    UPLOAD_FOLDER = (
        '/tmp/uploads'
        if os.environ.get('FLASK_ENV') == 'production'
        else os.path.join(basedir, 'uploads')
    )
    ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

    # Pagination
    COMPLAINTS_PER_PAGE = 10
    LOGS_PER_PAGE       = 20


class DevelopmentConfig(Config):
    DEBUG = True
    SESSION_COOKIE_SECURE  = False
    REMEMBER_COOKIE_SECURE = False


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE  = True
    REMEMBER_COOKIE_SECURE = True


config_map = {
    'development': DevelopmentConfig,
    'production':  ProductionConfig,
    'default':     DevelopmentConfig,
}
