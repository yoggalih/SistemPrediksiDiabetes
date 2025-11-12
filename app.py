import os
import requests
import json
import numpy as np
import pickle

from flask import Flask, render_template, request, redirect, url_for, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

# --- Konfigurasi dan Inisialisasi ---
app = Flask(__name__)

# Kunci Rahasia untuk Sesi (HARUS KUAT)
app.config['SECRET_KEY'] = 'kunci_rahasia_sistem_prediksi_diabetes_anda_yang_sangat_kuat'


# ====================================================================
# === KONFIGURASI DATABASE MYSQL (LARAGON) ===
# GANTI NILAI DI BAWAH INI SESUAI DENGAN PENGATURAN MYSQL LARAGON ANDA!
# Format: mysql+pymysql://user:password@host/database_name
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/diabetes_db' 

# REKOMENDASI LARAGON DEFAULT: 
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/diabetes_db'
# Jika user Laragon Anda 'root' tanpa password
# ====================================================================

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Konfigurasi reCAPTCHA v2 (Wajib diganti!)
app.config['RECAPTCHA_SITE_KEY'] = 'scret'  
app.config['RECAPTCHA_SECRET_KEY'] = 'scret' 

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 
login_manager.login_message = "Anda harus login untuk mengakses halaman ini."

# Load model & scaler
try:
    model = pickle.load(open('model/diabetes_model.pkl', 'rb'))
    scaler = pickle.load(open('model/scaler.pkl', 'rb'))
except FileNotFoundError:
    print("WARNING: Model/Scaler files not found. Prediction routes might fail.")
    model = None
    scaler = None

# --- MODEL DATABASE USER ---
class User(UserMixin, db.Model):
    # Kolom ini otomatis dibuat di MySQL saat db.create_all() dijalankan
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(512), nullable=False)

    def __init__(self, username, password_hash):
        self.username = username
        self.password_hash = password_hash

@login_manager.user_loader
def load_user(user_id):
    """Callback untuk memuat pengguna dari ID (menggunakan DB)."""
    # Menggunakan db.session.get() adalah metode yang disarankan di SQLAlchemy 2.0+
    return db.session.get(User, int(user_id))


# --- Fungsi reCAPTCHA Validation ---
def verify_recaptcha(response_token):
    """Mengirim token reCAPTCHA ke Google untuk diverifikasi."""
    payload = {
        'secret': app.config['RECAPTCHA_SECRET_KEY'],
        'response': response_token
    }
    try:
        r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
        result = r.json()
        return result.get('success', False)
    except Exception as e:
        print(f"Error during reCAPTCHA verification: {e}")
        # Jika ada kesalahan koneksi, untuk keamanan, tolak verifikasi
        return False


# --- Route Authentication ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('check_diabetes_page'))

    site_key = app.config['RECAPTCHA_SITE_KEY']

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        recaptcha_token = request.form.get('g-recaptcha-response')
        
        # 1. Validasi reCAPTCHA
        if not recaptcha_token or not verify_recaptcha(recaptcha_token):
            return render_template('login.html', error='Verifikasi CAPTCHA gagal. Silakan coba lagi.', site_key=site_key)

        # 2. Validasi User dan Password (Menggunakan DB)
        user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('check_diabetes_page'))
        else:
            return render_template('login.html', error='Nama pengguna atau kata sandi salah.', site_key=site_key)

    return render_template('login.html', site_key=site_key)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('check_diabetes_page'))

    site_key = app.config['RECAPTCHA_SITE_KEY']

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        recaptcha_token = request.form.get('g-recaptcha-response')

        # 1. Validasi reCAPTCHA
        if not recaptcha_token or not verify_recaptcha(recaptcha_token):
            return render_template('register.html', error='Verifikasi CAPTCHA gagal. Silakan coba lagi.', site_key=site_key)

        # 2. Cek apakah username sudah ada (Menggunakan DB)
        existing_user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()
        if existing_user:
            return render_template('register.html', error='Nama pengguna sudah terdaftar.', site_key=site_key)

        # 3. Buat user baru (Menggunakan DB)
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password_hash=hashed_password) 

        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        return redirect(url_for('check_diabetes_page'))

    return render_template('register.html', site_key=site_key)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('education'))


# --- Route Aplikasi Utama ---

@app.route('/')
@app.route('/education')
def education(): 
    # Pusat Edukasi adalah halaman publik (Home)
    return render_template('education.html', current_user=current_user)

@app.route('/check')
@login_required # Memastikan hanya yang login yang bisa melihat form
def check_diabetes_page():
    # index.html berisi form prediksi
    return render_template('index.html', current_user=current_user) 

@app.route('/predict', methods=['POST'])
@login_required 
def predict():
    # Ambil input dari form
    try:
        inputs = [
            float(request.form['Pregnancies']),
            float(request.form['Glucose']),
            float(request.form['BloodPressure']),
            float(request.form['SkinThickness']),
            float(request.form['Insulin']),
            float(request.form['BMI']),
            float(request.form['DiabetesPedigreeFunction']),
            float(request.form['Age'])
        ]

        # Ubah jadi numpy array dan scaling
        if model and scaler:
            final_input = np.array([inputs])
            scaled_input = scaler.transform(final_input)
            prediction = model.predict(scaled_input)[0]

            result_text = "⚠️ Anda berisiko diabetes" if prediction == 1 else "✅ Anda tidak berisiko diabetes"
        else:
            result_text = "ERROR: Model prediksi tidak dimuat. Cek log server."

        return render_template('result.html', result=result_text)
    except Exception as e:
        return render_template('result.html', result=f"Terjadi kesalahan: {e}")


if __name__ == "__main__":
    # Penting: Baris ini membuat tabel di database MySQL Anda (jika belum ada)
    with app.app_context():
        print("Mencoba membuat tabel di database MySQL...")
        db.create_all()
        print("Inisialisasi database selesai.")
    app.run(debug=True)
