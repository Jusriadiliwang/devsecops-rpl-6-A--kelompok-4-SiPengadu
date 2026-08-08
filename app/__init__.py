"""
Application factory untuk SiPengadu.
Pola ini memudahkan pengujian dan konfigurasi multi-environment.
"""
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from config import config_map
import os
from datetime import datetime

# Inisialisasi ekstensi (belum di-bind ke app instance)
db = SQLAlchemy()
login_manager = LoginManager()
bcrypt = Bcrypt()
csrf = CSRFProtect()

# ----------------------------------------------------------------
# FIX #2: Rate Limiter — cegah brute force pada endpoint login
# FIX #5: key_func=get_remote_address bekerja benar setelah ProxyFix
# ----------------------------------------------------------------
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],          # Tidak ada limit global; limit per-route saja
    storage_uri="memory://",    # In-memory (cukup untuk single-process dev)
)


def create_app(config_name='default'):
    """Buat dan konfigurasi instance Flask."""
    app = Flask(__name__)
    app.config.from_object(config_map[config_name])

    # ----------------------------------------------------------------
    # FIX #5: ProxyFix — tangani X-Forwarded-For dengan aman.
    # Tanpa ini, attacker bisa spoof IP dengan mengirim header palsu.
    # x_for=1 berarti percaya TEPAT 1 level proxy (nilai sesuai setup).
    # ----------------------------------------------------------------
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    # Bind ekstensi ke app
    db.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # ----------------------------------------------------------------
    # Konfigurasi Flask-Login
    # FIX MEDIUM: session_protection='strong' — Flask-Login akan
    # invalidate session jika IP atau User-Agent berubah drastis,
    # mengurangi risiko session hijacking.
    # ----------------------------------------------------------------
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Silakan login terlebih dahulu untuk mengakses halaman ini.'
    login_manager.login_message_category = 'warning'
    login_manager.session_protection = 'strong'

    # Pastikan folder upload ada
    os.makedirs(app.config.get('UPLOAD_FOLDER', 'uploads'), exist_ok=True)

    # Daftarkan Blueprint
    from app.routes.auth import auth_bp
    from app.routes.main import main_bp
    from app.routes.admin import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp, url_prefix='/admin')

    # Daftarkan error handler
    from app.routes.errors import register_error_handlers
    register_error_handlers(app)

    # ----------------------------------------------------------------
    # FIX #4: HTTP Security Headers via after_request.
    # Meta http-equiv TIDAK efektif di browser modern — headers ini
    # WAJIB dikirim sebagai actual HTTP response headers.
    # (OWASP A05:2021 - Security Misconfiguration)
    # ----------------------------------------------------------------
    @app.after_request
    def set_security_headers(response):
        # Cegah browser menebak-nebak MIME type (MIME sniffing attack)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        # Cegah halaman ini di-embed dalam iframe (clickjacking)
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        # Batasi informasi Referer yang dikirim ke domain lain
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        # Cegah browser cache halaman yang mungkin mengandung data sensitif
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'
        # Hapus header yang membocorkan teknologi stack
        response.headers.pop('Server', None)
        response.headers.pop('X-Powered-By', None)
        return response

    # Context processor: variabel global untuk semua template
    @app.context_processor
    def inject_globals():
        return {
            'current_year': datetime.utcnow().year,
            'app_name': 'SiPengadu',
        }

    return app
