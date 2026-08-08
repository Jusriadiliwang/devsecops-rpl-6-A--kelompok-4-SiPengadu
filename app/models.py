"""
Model database aplikasi SiPengadu.

Seluruh interaksi database dilakukan melalui SQLAlchemy ORM
untuk mencegah SQL Injection (OWASP A03:2021).
Password TIDAK PERNAH disimpan dalam bentuk plaintext —
hanya hash bcrypt yang disimpan (OWASP A02:2021).
"""
from datetime import datetime
from app import db, login_manager, bcrypt
from flask_login import UserMixin


# ================================================================
# Model Wilayah — definisikan LEBIH DULU agar FK dari User/Complaint
# dapat merujuk ke tabel ini.
# ================================================================

class Kecamatan(db.Model):
    """Model wilayah kecamatan."""
    __tablename__ = 'kecamatans'

    id         = db.Column(db.Integer, primary_key=True)
    name       = db.Column(db.String(100), nullable=False, unique=True)
    code       = db.Column(db.String(20),  nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Satu kecamatan memiliki banyak desa
    desas = db.relationship(
        'Desa',
        backref='kecamatan',
        lazy='dynamic',
        cascade='all, delete-orphan',
    )

    def __repr__(self):
        return f'<Kecamatan {self.name}>'


class Desa(db.Model):
    """Model wilayah desa / kelurahan."""
    __tablename__ = 'desas'

    id           = db.Column(db.Integer, primary_key=True)
    kecamatan_id = db.Column(db.Integer, db.ForeignKey('kecamatans.id'),
                             nullable=False, index=True)
    name         = db.Column(db.String(100), nullable=False)
    code         = db.Column(db.String(20),  nullable=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Desa {self.name}>'


# ================================================================
# Model Pengguna
# ================================================================

class User(UserMixin, db.Model):
    """Model pengguna sistem."""
    __tablename__ = 'users'

    # Daftar role yang valid
    ROLES = {
        'admin':            'Admin Pusat',
        'admin_kecamatan':  'Admin Kecamatan',
        'admin_desa':       'Admin Desa',
        'citizen':          'Masyarakat',
    }
    ADMIN_ROLES = {'admin', 'admin_kecamatan', 'admin_desa'}

    id          = db.Column(db.Integer, primary_key=True)
    username    = db.Column(db.String(50),  unique=True, nullable=False, index=True)
    email       = db.Column(db.String(100), unique=True, nullable=False, index=True)
    # ----------------------------------------------------------------
    # KEAMANAN: Simpan password_hash (bcrypt), BUKAN password asli.
    # ----------------------------------------------------------------
    password_hash = db.Column(db.String(255), nullable=False)
    full_name   = db.Column(db.String(100), nullable=False)
    phone       = db.Column(db.String(20))
    address     = db.Column(db.Text)
    # Foto profil: URL Cloudinary atau path lokal relatif terhadap uploads/
    avatar      = db.Column(db.String(500), nullable=True)
    # role: 'admin' | 'admin_kecamatan' | 'admin_desa' | 'citizen'
    role        = db.Column(db.String(20), default='citizen', nullable=False)
    is_active   = db.Column(db.Boolean, default=True, nullable=False)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at  = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Wilayah kerja (hanya untuk admin_kecamatan / admin_desa)
    kecamatan_id = db.Column(db.Integer, db.ForeignKey('kecamatans.id'), nullable=True)
    desa_id      = db.Column(db.Integer, db.ForeignKey('desas.id'),      nullable=True)

    # Relasi wilayah
    kecamatan = db.relationship('Kecamatan', foreign_keys=[kecamatan_id])
    desa      = db.relationship('Desa',      foreign_keys=[desa_id])

    # Relasi pengaduan
    complaints = db.relationship(
        'Complaint',
        foreign_keys='Complaint.user_id',
        backref='author',
        lazy='dynamic',
        cascade='all, delete-orphan',
    )
    reviewed_complaints = db.relationship(
        'Complaint',
        foreign_keys='Complaint.reviewed_by',
        backref='reviewer',
        lazy='dynamic',
    )
    logs = db.relationship('ActivityLog', backref='user', lazy='dynamic')

    # ----------------------------------------------------------------
    def set_password(self, password: str) -> None:
        """Hash password dengan bcrypt sebelum disimpan ke database."""
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password: str) -> bool:
        """Verifikasi password terhadap hash bcrypt yang tersimpan."""
        return bcrypt.check_password_hash(self.password_hash, password)

    def is_admin(self) -> bool:
        """True untuk semua role admin (pusat, kecamatan, desa)."""
        return self.role in self.ADMIN_ROLES

    def is_superadmin(self) -> bool:
        """True hanya untuk admin pusat (role='admin')."""
        return self.role == 'admin'

    def is_local_admin(self) -> bool:
        """True untuk admin_kecamatan dan admin_desa."""
        return self.role in {'admin_kecamatan', 'admin_desa'}

    def get_role_label(self) -> str:
        return self.ROLES.get(self.role, self.role)

    def __repr__(self):
        return f'<User {self.username} [{self.role}]>'


@login_manager.user_loader
def load_user(user_id: str):
    """
    Callback Flask-Login: muat pengguna dari session.

    FIX #3: Validasi session fingerprint (_pf) terhadap hash password
    yang tersimpan di database. Jika password telah diubah di sesi/
    perangkat lain, fingerprint tidak cocok dan session ini di-invalidate
    otomatis — pengguna wajib login ulang.
    (OWASP A07:2021 - Identification and Authentication Failures)
    """
    from flask import session as flask_session
    try:
        user = db.session.get(User, int(user_id))
        if user is None:
            return None

        stored_fp = flask_session.get('_pf', '')
        # Jika _pf ada di session, validasi terhadap hash saat ini
        if stored_fp and stored_fp != user.password_hash[-10:]:
            # Password telah diubah di sesi/perangkat lain → tolak session ini
            flask_session.clear()
            return None

        return user
    except Exception:
        return None


# ================================================================
# Model Pengaduan
# ================================================================

class Complaint(db.Model):
    """Model pengaduan masyarakat."""
    __tablename__ = 'complaints'

    CATEGORIES = [
        ('infrastructure',  'Infrastruktur'),
        ('public_service',  'Pelayanan Publik'),
        ('environment',     'Lingkungan Hidup'),
        ('social',          'Masalah Sosial'),
        ('security',        'Keamanan & Ketertiban'),
        ('other',           'Lainnya'),
    ]

    STATUSES = [
        ('pending',   'Menunggu'),
        ('in_review', 'Sedang Ditinjau'),
        ('resolved',  'Selesai'),
        ('rejected',  'Ditolak'),
    ]

    STATUS_BADGE = {
        'pending':   'bg-warning text-dark',
        'in_review': 'bg-info text-white',
        'resolved':  'bg-success',
        'rejected':  'bg-danger',
    }

    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    title        = db.Column(db.String(200), nullable=False)
    description  = db.Column(db.Text, nullable=False)
    category     = db.Column(db.String(50),  nullable=False)
    location     = db.Column(db.String(200), nullable=False)
    status       = db.Column(db.String(20),  default='pending', nullable=False, index=True)
    admin_response = db.Column(db.Text)
    reviewed_by  = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at   = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Wilayah pengaduan
    kecamatan_id = db.Column(db.Integer, db.ForeignKey('kecamatans.id'), nullable=True, index=True)
    desa_id      = db.Column(db.Integer, db.ForeignKey('desas.id'),      nullable=True, index=True)

    # Relasi wilayah
    kecamatan = db.relationship('Kecamatan', foreign_keys=[kecamatan_id])
    desa      = db.relationship('Desa',      foreign_keys=[desa_id])

    def get_category_label(self) -> str:
        return dict(self.CATEGORIES).get(self.category, self.category)

    def get_status_label(self) -> str:
        return dict(self.STATUSES).get(self.status, self.status)

    def get_status_badge(self) -> str:
        return self.STATUS_BADGE.get(self.status, 'bg-secondary')

    # Relasi foto
    photos = db.relationship(
        'ComplaintPhoto',
        backref='complaint',
        lazy='dynamic',
        cascade='all, delete-orphan',
    )

    def __repr__(self):
        return f'<Complaint #{self.id}: {self.title[:40]}>'


class ComplaintPhoto(db.Model):
    """
    Foto/bukti pendukung pengaduan.
    Setiap pengaduan dapat memiliki hingga 5 foto.
    URL disimpan sebagai Cloudinary URL (production) atau path lokal (dev).
    """
    __tablename__ = 'complaint_photos'

    id           = db.Column(db.Integer, primary_key=True)
    complaint_id = db.Column(db.Integer, db.ForeignKey('complaints.id'), nullable=False, index=True)
    # URL Cloudinary atau path lokal relatif terhadap uploads/
    url          = db.Column(db.String(500), nullable=False)
    # public_id Cloudinary (untuk delete), kosong jika lokal
    public_id    = db.Column(db.String(200), nullable=True)
    filename     = db.Column(db.String(200), nullable=True)
    uploaded_at  = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ComplaintPhoto #{self.id} for complaint #{self.complaint_id}>'


class ActivityLog(db.Model):
    """
    Log aktivitas keamanan yang relevan.
    Mencatat: login berhasil/gagal, logout, perubahan data penting,
    perubahan hak akses, dan percobaan akses yang ditolak.
    """
    __tablename__ = 'activity_logs'

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action     = db.Column(db.String(100), nullable=False)
    details    = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def __repr__(self):
        return f'<ActivityLog [{self.action}] @ {self.timestamp}>'
