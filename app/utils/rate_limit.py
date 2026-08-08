"""
Rate limiter sederhana berbasis in-memory.
Menggantikan Flask-Limiter agar Lambda Vercel tetap kecil.
Pada serverless (Vercel), counter reset di setiap cold-start — cukup
untuk mencegah burst attack dalam satu invokasi.
"""
import time
from collections import defaultdict
from functools import wraps
from threading import Lock

_lock = Lock()
_requests: dict = defaultdict(list)  # key -> [timestamps]


def rate_limit(calls: int, period: int = 60,
               message: str = "Terlalu banyak percobaan. Coba lagi nanti."):
    """
    Decorator rate limiter per IP + endpoint.

    Contoh pemakaian:
        @auth_bp.route('/login', methods=['GET', 'POST'])
        @rate_limit(5, 60, "Maksimal 5 percobaan login per menit.")
        def login(): ...
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            from flask import request, flash, abort
            key = f"{request.remote_addr or 'unknown'}:{f.__name__}"
            now = time.time()
            with _lock:
                # Buang entri yang sudah kedaluwarsa
                _requests[key] = [t for t in _requests[key] if now - t < period]
                if len(_requests[key]) >= calls:
                    flash(message, 'danger')
                    abort(429)
                _requests[key].append(now)
            return f(*args, **kwargs)
        return wrapper
    return decorator
