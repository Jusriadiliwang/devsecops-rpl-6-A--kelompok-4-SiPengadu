"""
Entry point aplikasi SiPengadu.
Muat .env SEBELUM mengimpor modul apapun yang membaca os.environ.
"""
import os

# Muat environment variables dari file .env
from dotenv import load_dotenv
load_dotenv()

from app import create_app, db
from app.models import User

app = create_app(os.getenv('FLASK_ENV', 'development'))


def init_db():
    """Inisialisasi tabel database dan buat akun admin default."""
    with app.app_context():
        db.create_all()

        # Buat akun admin pertama jika belum ada
        if not User.query.filter_by(role='admin').first():
            admin_password = os.getenv('ADMIN_PASSWORD', 'Admin@Default2025!')
            admin = User(
                username='admin',
                email='admin@sipengadu.local',
                full_name='Administrator Sistem',
                role='admin',
                is_active=True,
            )
            admin.set_password(admin_password)
            db.session.add(admin)
            db.session.commit()
            print('[INIT] Akun admin berhasil dibuat. Username: admin')
            # FIX MEDIUM: JANGAN print password ke stdout/log.
            # Password dibaca dari variabel ADMIN_PASSWORD di .env.
            print('[INIT] Password: lihat variabel ADMIN_PASSWORD di file .env')
            print('[INIT] Segera ubah password admin setelah login pertama!')
        else:
            print('[INIT] Akun admin sudah ada, lewati pembuatan.')


if __name__ == '__main__':
    flask_env = os.getenv('FLASK_ENV', 'development')

    # FIX MEDIUM: Cegah aplikasi dijalankan dengan DEBUG=True di production
    if flask_env == 'production' and app.config.get('DEBUG'):
        raise RuntimeError(
            '[KEAMANAN] DEBUG=True tidak boleh aktif di environment production! '
            'Set FLASK_ENV=production di file .env'
        )

    os.makedirs('instance', exist_ok=True)
    os.makedirs('uploads', exist_ok=True)
    init_db()
    print('[INFO] Aplikasi berjalan di http://127.0.0.1:5000')
    app.run(host='127.0.0.1', port=5000, debug=app.config['DEBUG'])
