"""
Entry point aplikasi SiPengadu.
Muat .env SEBELUM mengimpor modul apapun yang membaca os.environ.
"""
import os

# Muat environment variables dari file .env (hanya efektif di lokal)
from dotenv import load_dotenv
load_dotenv()

from app import create_app, db
from app.models import User, Kecamatan, Desa

# app harus di top-level agar Vercel bisa import langsung
app = create_app(os.getenv('FLASK_ENV', 'development'))


@app.route('/init-db')
def init_db_route():
    """
    Route sementara untuk inisialisasi database di production.
    HAPUS atau NONAKTIFKAN setelah database berhasil diinisialisasi!
    Akses: GET /init-db
    """
    init_token = os.getenv('INIT_DB_TOKEN', '')
    from flask import request, jsonify
    token = request.args.get('token', '')
    if init_token and token != init_token:
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        init_db()
        return jsonify({'status': 'ok', 'message': 'Database berhasil diinisialisasi.'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


def init_db():
    """Inisialisasi tabel database dan buat akun admin default."""
    with app.app_context():
        db.create_all()

        # Seed kecamatan default jika belum ada
        if not Kecamatan.query.first():
            kec_data = [
                {'name': 'Rappocini', 'code': 'RPC'},
                {'name': 'Tamalate', 'code': 'TML'},
            ]
            for k in kec_data:
                kec = Kecamatan(name=k['name'], code=k['code'])
                db.session.add(kec)
            db.session.flush()

            desa_data = [
                {'name': 'Rappocini', 'kecamatan': 'Rappocini'},
                {'name': 'Karunrung', 'kecamatan': 'Rappocini'},
                {'name': 'Bonto Makkio', 'kecamatan': 'Rappocini'},
                {'name': 'Balang Baru', 'kecamatan': 'Tamalate'},
                {'name': 'Parang Tambung', 'kecamatan': 'Tamalate'},
            ]
            for d in desa_data:
                kec = Kecamatan.query.filter_by(name=d['kecamatan']).first()
                if kec:
                    desa = Desa(name=d['name'], kecamatan_id=kec.id)
                    db.session.add(desa)
            db.session.commit()
            print('[INIT] Kecamatan dan Desa berhasil di-seed.')

        # Buat akun admin pertama jika belum ada
        if not User.query.filter_by(role='admin').first():
            admin_password = os.getenv('ADMIN_PASSWORD', 'Admin@Pengaduan2025!')
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
            print('[INIT] Akun admin berhasil dibuat.')
        else:
            print('[INIT] Akun admin sudah ada, lewati pembuatan.')


if __name__ == '__main__':
    flask_env = os.getenv('FLASK_ENV', 'development')

    # Cegah aplikasi dijalankan dengan DEBUG=True di production
    if flask_env == 'production' and app.config.get('DEBUG'):
        raise RuntimeError(
            '[KEAMANAN] DEBUG=True tidak boleh aktif di environment production!'
        )

    os.makedirs('instance', exist_ok=True)
    os.makedirs('uploads', exist_ok=True)
    init_db()
    print('[INFO] Aplikasi berjalan di http://127.0.0.1:5000')
    app.run(host='127.0.0.1', port=5000, debug=app.config['DEBUG'])
