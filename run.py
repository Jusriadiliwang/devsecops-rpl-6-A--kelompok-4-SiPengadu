"""
Entry point aplikasi SiPengadu.
Muat .env SEBELUM mengimpor modul apapun yang membaca os.environ.
"""
import os
import traceback as _tb

# ----------------------------------------------------------------
# PENTING: Vercel melakukan static scan untuk nama 'app' di top-level.
# Deklarasikan dulu sebelum try/except agar scanner menemukannya.
# Nilai akan di-assign ulang oleh blok try/except di bawah.
# ----------------------------------------------------------------
app = None  # noqa: E402  — Vercel top-level entrypoint marker

# Muat environment variables dari file .env (hanya efektif di lokal)
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# ----------------------------------------------------------------
# Bungkus import dalam try-except agar error tampil di browser
# sebagai JSON (bukan "Serverless Function crashed" yang tidak
# memberikan informasi apapun).
# ----------------------------------------------------------------
_init_error = None
_init_tb = None

try:
    from app import create_app, db
    from app.models import User, Kecamatan, Desa
    app = create_app(os.getenv('FLASK_ENV', 'development'))
except Exception as _e:
    _init_error = str(_e)
    _init_tb = _tb.format_exc()

    # Buat Flask minimal yang hanya menampilkan error
    from flask import Flask as _Flask, jsonify as _jsonify
    app = _Flask(__name__)

    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>')
    def _show_error(path=''):
        return _jsonify({
            'status': 'init_error',
            'error': _init_error,
            'traceback': _init_tb,
        }), 500


@app.route('/init-db')
def init_db_route():
    """Route untuk inisialisasi database PostgreSQL setelah deploy."""
    if _init_error:
        from flask import jsonify
        return jsonify({'status': 'error', 'error': _init_error, 'traceback': _init_tb}), 500
    init_token = os.getenv('INIT_DB_TOKEN', '')
    from flask import request, jsonify
    token = request.args.get('token', '')
    if init_token and token != init_token:
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        init_db()
        return jsonify({'status': 'ok', 'message': 'Database berhasil diinisialisasi.'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e), 'traceback': _tb.format_exc()}), 500


def init_db():
    """Inisialisasi tabel database dan seed data awal."""
    with app.app_context():
        db.create_all()

        # Seed kecamatan default jika belum ada
        if not Kecamatan.query.first():
            kec_data = [
                {'name': 'Rappocini', 'code': 'RPC'},
                {'name': 'Tamalate', 'code': 'TML'},
            ]
            kec_map = {}
            for k in kec_data:
                kec = Kecamatan(name=k['name'], code=k['code'])
                db.session.add(kec)
                db.session.flush()
                kec_map[k['name']] = kec.id

            desa_data = [
                {'name': 'Rappocini', 'kecamatan': 'Rappocini'},
                {'name': 'Karunrung', 'kecamatan': 'Rappocini'},
                {'name': 'Bonto Makkio', 'kecamatan': 'Rappocini'},
                {'name': 'Balang Baru', 'kecamatan': 'Tamalate'},
                {'name': 'Parang Tambung', 'kecamatan': 'Tamalate'},
            ]
            for d in desa_data:
                desa = Desa(name=d['name'], kecamatan_id=kec_map[d['kecamatan']])
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
            print('[INIT] Akun admin sudah ada.')


if __name__ == '__main__':
    flask_env = os.getenv('FLASK_ENV', 'development')

    if flask_env == 'production' and app.config.get('DEBUG'):
        raise RuntimeError('[KEAMANAN] DEBUG=True tidak boleh aktif di production!')

    os.makedirs('instance', exist_ok=True)
    os.makedirs('uploads', exist_ok=True)
    init_db()
    print('[INFO] Aplikasi berjalan di http://127.0.0.1:5000')
    app.run(host='127.0.0.1', port=5000, debug=app.config['DEBUG'])
