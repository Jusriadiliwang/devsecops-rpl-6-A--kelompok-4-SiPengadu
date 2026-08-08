"""
Form aplikasi SiPengadu menggunakan Flask-WTF + WTForms.

Setiap form secara otomatis mendapatkan CSRF token melalui
{{ form.hidden_tag() }} di template — mencegah CSRF Attack
(OWASP A01:2021 - Broken Access Control).

Validasi sisi server WAJIB dilakukan di sini; jangan andalkan
validasi sisi klien (JavaScript) saja.
"""
import re
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, MultipleFileField
from wtforms import (
    StringField, PasswordField, TextAreaField,
    SelectField, BooleanField, SubmitField,
)
from wtforms.validators import (
    DataRequired, Length, Email, EqualTo,
    ValidationError, Regexp, Optional,
)


# ----------------------------------------------------------------
# Validator kustom: kekuatan password
# ----------------------------------------------------------------
def _password_strength(form, field):
    """
    Password harus memenuhi kriteria:
    - Minimal 1 huruf kapital
    - Minimal 1 huruf kecil
    - Minimal 1 angka
    - Minimal 1 karakter spesial
    """
    pw = field.data or ''
    missing = []
    if not re.search(r'[A-Z]', pw):
        missing.append('huruf kapital')
    if not re.search(r'[a-z]', pw):
        missing.append('huruf kecil')
    if not re.search(r'[0-9]', pw):
        missing.append('angka')
    if not re.search(r'[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]', pw):
        missing.append('karakter spesial (!@#$%...)')
    if missing:
        raise ValidationError(f"Password harus mengandung: {', '.join(missing)}.")


# ================================================================
# Form Autentikasi
# ================================================================

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message='Username wajib diisi.'),
        Length(min=3, max=50, message='Username harus 3–50 karakter.'),
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='Password wajib diisi.'),
    ])
    remember_me = BooleanField('Ingat Saya')
    submit = SubmitField('Masuk')


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message='Username wajib diisi.'),
        Length(min=3, max=50, message='Username harus 3–50 karakter.'),
        Regexp(
            r'^[a-zA-Z0-9_]+$',
            message='Username hanya boleh berisi huruf, angka, dan underscore (_).',
        ),
    ])
    email = StringField('Email', validators=[
        DataRequired(message='Email wajib diisi.'),
        Email(message='Format email tidak valid.'),
        Length(max=100),
    ])
    full_name = StringField('Nama Lengkap', validators=[
        DataRequired(message='Nama lengkap wajib diisi.'),
        Length(min=2, max=100, message='Nama harus 2–100 karakter.'),
    ])
    phone = StringField('Nomor Telepon', validators=[
        Optional(),
        Length(max=20),
        Regexp(r'^[0-9+\-\s]*$', message='Format nomor telepon tidak valid.'),
    ])
    address = TextAreaField('Alamat', validators=[
        Optional(),
        Length(max=500),
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='Password wajib diisi.'),
        Length(min=8, message='Password minimal 8 karakter.'),
        _password_strength,
    ])
    confirm_password = PasswordField('Konfirmasi Password', validators=[
        DataRequired(message='Konfirmasi password wajib diisi.'),
        EqualTo('password', message='Konfirmasi password tidak cocok.'),
    ])
    submit = SubmitField('Daftar Sekarang')


# ================================================================
# Form Profil
# ================================================================

class ProfileForm(FlaskForm):
    full_name = StringField('Nama Lengkap', validators=[
        DataRequired(message='Nama lengkap wajib diisi.'),
        Length(min=2, max=100),
    ])
    email = StringField('Email', validators=[
        DataRequired(message='Email wajib diisi.'),
        Email(message='Format email tidak valid.'),
        Length(max=100),
    ])
    phone = StringField('Nomor Telepon', validators=[
        Optional(),
        Length(max=20),
        Regexp(r'^[0-9+\-\s]*$', message='Format nomor telepon tidak valid.'),
    ])
    address = TextAreaField('Alamat', validators=[
        Optional(),
        Length(max=500),
    ])
    avatar = FileField('Foto Profil', validators=[
        Optional(),
        FileAllowed(['jpg', 'jpeg', 'png', 'webp'], 'Hanya file JPG, PNG, atau WEBP yang diizinkan.'),
    ])
    submit = SubmitField('Simpan Perubahan')


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Password Saat Ini', validators=[
        DataRequired(message='Password saat ini wajib diisi.'),
    ])
    new_password = PasswordField('Password Baru', validators=[
        DataRequired(message='Password baru wajib diisi.'),
        Length(min=8, message='Password minimal 8 karakter.'),
        _password_strength,
    ])
    confirm_password = PasswordField('Konfirmasi Password Baru', validators=[
        DataRequired(message='Konfirmasi password wajib diisi.'),
        EqualTo('new_password', message='Konfirmasi password tidak cocok.'),
    ])
    submit = SubmitField('Ubah Password')


# ================================================================
# Form Pengaduan
# ================================================================

class ComplaintForm(FlaskForm):
    title = StringField('Judul Pengaduan', validators=[
        DataRequired(message='Judul wajib diisi.'),
        Length(min=10, max=200, message='Judul harus 10–200 karakter.'),
    ])
    category = SelectField('Kategori', validators=[
        DataRequired(message='Kategori wajib dipilih.'),
    ], choices=[
        ('',              '-- Pilih Kategori --'),
        ('infrastructure','Infrastruktur'),
        ('public_service','Pelayanan Publik'),
        ('environment',   'Lingkungan Hidup'),
        ('social',        'Masalah Sosial'),
        ('security',      'Keamanan & Ketertiban'),
        ('other',         'Lainnya'),
    ])
    location = StringField('Lokasi Kejadian', validators=[
        DataRequired(message='Lokasi wajib diisi.'),
        Length(min=5, max=200, message='Lokasi harus 5–200 karakter.'),
    ])
    # Wilayah — opsional; choices diisi di route handler
    kecamatan_id = SelectField('Kecamatan', coerce=int, validators=[Optional()])
    desa_id      = SelectField('Desa / Kelurahan', coerce=int, validators=[Optional()])
    description = TextAreaField('Deskripsi Pengaduan', validators=[
        DataRequired(message='Deskripsi wajib diisi.'),
        Length(min=20, max=2000, message='Deskripsi harus 20–2000 karakter.'),
    ])
    photos = MultipleFileField('Foto Bukti (maks. 5 foto)', validators=[
        Optional(),
        FileAllowed(['jpg', 'jpeg', 'png', 'webp'], 'Hanya file JPG, PNG, atau WEBP yang diizinkan.'),
    ])
    submit = SubmitField('Kirim Pengaduan')


# ================================================================
# Form Admin
# ================================================================

class AdminResponseForm(FlaskForm):
    status = SelectField('Status Pengaduan', validators=[
        DataRequired(message='Status wajib dipilih.'),
    ], choices=[
        ('pending',   'Menunggu'),
        ('in_review', 'Sedang Ditinjau'),
        ('resolved',  'Diselesaikan'),
        ('rejected',  'Ditolak'),
    ])
    admin_response = TextAreaField('Tanggapan / Keterangan', validators=[
        Optional(),
        Length(max=1000, message='Tanggapan maksimal 1000 karakter.'),
    ])
    submit = SubmitField('Perbarui Status')


class AdminEditUserForm(FlaskForm):
    full_name = StringField('Nama Lengkap', validators=[
        DataRequired(message='Nama wajib diisi.'),
        Length(min=2, max=100),
    ])
    email = StringField('Email', validators=[
        DataRequired(message='Email wajib diisi.'),
        Email(message='Format email tidak valid.'),
        Length(max=100),
    ])
    role = SelectField('Peran', validators=[
        DataRequired(),
    ], choices=[
        ('citizen',          'Masyarakat'),
        ('admin',            'Admin Pusat'),
        ('admin_kecamatan',  'Admin Kecamatan'),
        ('admin_desa',       'Admin Desa'),
    ])
    is_active = BooleanField('Akun Aktif')
    submit = SubmitField('Simpan Perubahan')


# ================================================================
# Form Kelola Wilayah (superadmin only)
# ================================================================

class KecamatanForm(FlaskForm):
    name = StringField('Nama Kecamatan', validators=[
        DataRequired(message='Nama kecamatan wajib diisi.'),
        Length(min=2, max=100, message='Nama harus 2–100 karakter.'),
    ])
    code = StringField('Kode Wilayah', validators=[
        Optional(),
        Length(max=20, message='Kode maksimal 20 karakter.'),
    ])
    submit = SubmitField('Simpan')


class DesaForm(FlaskForm):
    # choices diisi di route handler
    kecamatan_id = SelectField('Kecamatan', coerce=int, validators=[
        DataRequired(message='Kecamatan wajib dipilih.'),
    ])
    name = StringField('Nama Desa / Kelurahan', validators=[
        DataRequired(message='Nama desa wajib diisi.'),
        Length(min=2, max=100, message='Nama harus 2–100 karakter.'),
    ])
    code = StringField('Kode Wilayah', validators=[
        Optional(),
        Length(max=20, message='Kode maksimal 20 karakter.'),
    ])
    submit = SubmitField('Simpan')


class CreateLocalAdminForm(FlaskForm):
    """Form untuk membuat akun admin lokal (kecamatan / desa)."""
    username = StringField('Username', validators=[
        DataRequired(message='Username wajib diisi.'),
        Length(min=3, max=50, message='Username harus 3–50 karakter.'),
        Regexp(
            r'^[a-zA-Z0-9_]+$',
            message='Username hanya boleh berisi huruf, angka, dan underscore.',
        ),
    ])
    email = StringField('Email', validators=[
        DataRequired(message='Email wajib diisi.'),
        Email(message='Format email tidak valid.'),
        Length(max=100),
    ])
    full_name = StringField('Nama Lengkap', validators=[
        DataRequired(message='Nama lengkap wajib diisi.'),
        Length(min=2, max=100),
    ])
    phone = StringField('Nomor Telepon', validators=[
        Optional(),
        Length(max=20),
        Regexp(r'^[0-9+\-\s]*$', message='Format nomor telepon tidak valid.'),
    ])
    role = SelectField('Role Admin', validators=[
        DataRequired(),
    ], choices=[
        ('admin_kecamatan', 'Admin Kecamatan'),
        ('admin_desa',      'Admin Desa'),
    ])
    # choices diisi di route handler
    kecamatan_id = SelectField('Kecamatan', coerce=int, validators=[Optional()])
    desa_id      = SelectField('Desa / Kelurahan', coerce=int, validators=[Optional()])
    password = PasswordField('Password', validators=[
        DataRequired(message='Password wajib diisi.'),
        Length(min=8, message='Password minimal 8 karakter.'),
        _password_strength,
    ])
    confirm_password = PasswordField('Konfirmasi Password', validators=[
        DataRequired(message='Konfirmasi password wajib diisi.'),
        EqualTo('password', message='Konfirmasi password tidak cocok.'),
    ])
    submit = SubmitField('Buat Akun Admin')
