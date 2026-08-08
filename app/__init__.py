"""
Application factory untuk SiPengadu.
Pola ini memudahkan pengujian dan konfigurasi multi-environment.
"""
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
from config import config_map
import os
from datetime import datetime

# Inisialisasi ekstensi (belum di-bind ke app instance)
db = SQLAlchemy()
login_manager = LoginManager()
bcrypt = Bcrypt()
csrf = CSRFProtect()

# Compat stub — auth.py mengimpor 'limiter' dari sini.
# Rate limiting kini ditangani oleh app.utils.rate_limit.rate_limit decorator.
class _LimiterStub:
    """Stub agar import 'from app import limiter' di auth.py tidak error."""
    def limit(self, *args, **kwargs):
        def decorator(f):
            return f
        return decorator
    def init_app(self, app):
        pass

limiter = _LimiterStub()


def create_app(config_name='default'):
    """Buat dan konfigurasi instance Flask."""
    app = Flask(__name__)
    app.config.from_object(config_map[config_name])

    # ----------------------------------------------------------------
    # FIX #5: ProxyFix — tangani X-Forwarded-For dengan aman.
    # ----------------------------------------------------------------
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    # Bind ekstensi ke app
    db.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    csrf.init_app(app)

    # ----------------------------------------------------------------
    # Konfigurasi Flask-Login
    # ----------------------------------------------------------------
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Silakan login terlebih dahulu untuk mengakses halaman ini.'
    login_manager.login_message_category = 'warning'
    login_manager.session_protection = 'strong'

    # Pastikan folder upload ada (try-except karena Vercel read-only fs)
    try:
        os.makedirs(app.config.get('UPLOAD_FOLDER', 'uploads'), exist_ok=True)
    except OSError:
        pass

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
    # ----------------------------------------------------------------
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'
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
