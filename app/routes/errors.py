"""
Handler error HTTP.

KEAMANAN: Error handler menampilkan pesan generik kepada pengguna.
Detail teknis (stack trace, nama tabel, query SQL, dll.) TIDAK
boleh terekspos ke pengguna akhir — hanya disimpan di log server.
Ini mencegah Information Disclosure (OWASP A05:2021).
"""
from flask import render_template
from app import db


def register_error_handlers(app):
    """Daftarkan handler untuk kode HTTP error umum."""

    @app.errorhandler(400)
    def bad_request(e):
        return render_template('errors/400.html'), 400

    @app.errorhandler(403)
    def forbidden(e):
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(413)
    def request_entity_too_large(e):
        return render_template('errors/413.html'), 413

    # ----------------------------------------------------------------
    # Handler 429: Terlalu Banyak Request (Rate Limit Exceeded)
    # Dipicu oleh Flask-Limiter ketika batas percobaan login terlampaui.
    # ----------------------------------------------------------------
    @app.errorhandler(429)
    def too_many_requests(e):
        return render_template('errors/429.html'), 429

    @app.errorhandler(500)
    def internal_error(e):
        # Rollback transaksi yang mungkin gagal
        db.session.rollback()
        # ----------------------------------------------------------------
        # KEAMANAN: Tampilkan pesan generik — JANGAN bocorkan detail error
        # ----------------------------------------------------------------
        return render_template('errors/500.html'), 500

