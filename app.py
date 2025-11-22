import os
import requests
import json
import numpy as np
import pickle
from datetime import datetime # DITAMBAHKAN: Untuk menyimpan tanggal prediksi

from flask import Flask, render_template, request, redirect, url_for, session, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy


# --- Konfigurasi dan Inisialisasi ---
app = Flask(__name__)

# ====================================================================
# === KONFIGURASI DATABASE MYSQL (LARAGON) ===
# GANTI NILAI DI BAWAH INI SESUAI DENGAN PENGATURAN MYSQL LARAGON ANDA!
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/diabetes_db' 
# ====================================================================

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Konfigurasi reCAPTCHA v2 (Wajib diganti!)
app.config['RECAPTCHA_SITE_KEY'] = '6LctWgosAAAAACBPh7DXH6P3o_220BhNMr2LWFLN'  
app.config['RECAPTCHA_SECRET_KEY'] = '6LctWgosAAAAAAvFWOFup2WAn0HFygryp8K9jd1t' 


# Kunci Rahasia untuk Sesi (HARUS KUAT)
app.config['SECRET_KEY'] = '6LctWgosAAAAAAvFWOFup2WAn0HFygryp8K9jd1t'

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

# --- MODEL DATABASE USER & HISTORY (DITAMBAHKAN) ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(512), nullable=False)
    # Tambahkan relasi ke PredictionHistory
    predictions = db.relationship('PredictionHistory', backref='predictor', lazy='dynamic') # DITAMBAHKAN

    def __init__(self, username, password_hash):
        self.username = username
        self.password_hash = password_hash

class PredictionHistory(db.Model): # DITAMBAHKAN
    """Model untuk menyimpan riwayat hasil prediksi setiap pengguna."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    prediction_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Data Input
    pregnancies = db.Column(db.Float, nullable=False)
    glucose = db.Column(db.Float, nullable=False)
    blood_pressure = db.Column(db.Float, nullable=False)
    skin_thickness = db.Column(db.Float, nullable=False)
    insulin = db.Column(db.Float, nullable=False)
    bmi = db.Column(db.Float, nullable=False)
    dpf = db.Column(db.Float, nullable=False) # DiabetesPedigreeFunction
    age = db.Column(db.Float, nullable=False)
    
    # Data Hasil
    prediction_class = db.Column(db.Integer, nullable=False) # 0 or 1
    probability = db.Column(db.Float, nullable=False)
    risk_level = db.Column(db.String(50), nullable=False)
    
@login_manager.user_loader
def load_user(user_id):
    """Callback untuk memuat pengguna dari ID (menggunakan DB)."""
    return db.session.get(User, int(user_id))


# --- Fungsi reCAPTCHA Validation (TETAP) ---
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
        return False


# --- Route Authentication (TETAP) ---

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
    return render_template('education.html', current_user=current_user)

@app.route('/check')
@login_required 
def check_diabetes_page():
    # index.html berisi form prediksi
    return render_template('index.html', current_user=current_user) 

@app.route('/history') # DITAMBAHKAN: Route untuk melihat riwayat
@login_required 
def prediction_history_page():
    # Ambil riwayat prediksi pengguna saat ini, diurutkan berdasarkan tanggal terbaru
    history_records = db.session.execute(
        db.select(PredictionHistory)
        .filter_by(user_id=current_user.id)
        .order_by(PredictionHistory.prediction_date.desc())
    ).scalars().all()

    # Kirim data ke template baru (history.html)
    return render_template('history.html', history=history_records, current_user=current_user)


@app.route('/predict', methods=['POST'])
@login_required 
def predict():
    # Ambil input dari form
    feature_names = ['Pregnancies', 'Glucose', 'BloodPressure', 'SkinThickness', 'Insulin', 'BMI', 'DiabetesPedigreeFunction', 'Age']

    default_context = {
        'prediction': 0,
        'probability': '0.00%',
        'probability_raw': 0.0,
        'risk_level': 'Tidak Diketahui',
        'input_data': {name: 'N/A' for name in feature_names},
    }

    try:
        # Ambil nilai input
        input_values = {name: float(request.form[name]) for name in feature_names}
        inputs = list(input_values.values())
        
        # Inisialisasi variabel hasil
        prediction = 0
        prediction_proba = 0.0
        risk_level = 'Tidak Diketahui'

        if model and scaler:
            final_input = np.array([inputs])
            scaled_input = scaler.transform(final_input)
            
            # Prediksi kelas (0 atau 1)
            prediction = int(model.predict(scaled_input)[0])
            
            # Prediksi probabilitas untuk kelas 1 (risiko diabetes)
            prediction_proba = model.predict_proba(scaled_input)[0][1] * 100 
            
            # Menentukan risk_level
            if prediction_proba >= 70:
                risk_level = "Sangat Tinggi"
            elif prediction_proba >= 50:
                risk_level = "Tinggi"
            elif prediction_proba >= 30:
                risk_level = "Sedang"
            else:
                risk_level = "Rendah"
        
        # --- PENYIMPANAN RIWAYAT BARU (DITAMBAHKAN) ---
        new_history = PredictionHistory(
            user_id=current_user.id,
            pregnancies=input_values['Pregnancies'],
            glucose=input_values['Glucose'],
            blood_pressure=input_values['BloodPressure'],
            skin_thickness=input_values['SkinThickness'],
            insulin=input_values['Insulin'],
            bmi=input_values['BMI'],
            dpf=input_values['DiabetesPedigreeFunction'],
            age=input_values['Age'],
            prediction_class=prediction,
            probability=prediction_proba,
            risk_level=risk_level,
            prediction_date=datetime.utcnow() 
        )
        db.session.add(new_history)
        db.session.commit()
        # --- AKHIR PENYIMPANAN RIWAYAT ---

        return render_template(
            'result.html', 
            prediction=prediction,       
            probability=f"{prediction_proba:.2f}%",  
            probability_raw=prediction_proba, 
            risk_level=risk_level,            
            input_data=input_values,          
        )
            
    except ValueError:
        return render_template('result.html', result_error="Input tidak valid. Pastikan semua kolom diisi dengan angka dan bukan teks. Cek panduan pengisian.", **default_context)
    except Exception as e:
        return render_template('result.html', result_error=f"Terjadi kesalahan saat memproses data: {e}", **default_context)

@app.route('/history/<int:prediction_id>')
@login_required
def prediction_detail(prediction_id):
    # 1. Cari data berdasarkan ID dan pastikan milik user yang sedang login
    record = db.session.execute(
        db.select(PredictionHistory)
        .filter_by(id=prediction_id, user_id=current_user.id)
    ).scalar_one_or_none()

    # 2. Jika tidak ketemu, tampilkan error 404
    if record is None:
        abort(404)

    # 3. Format ulang data agar sesuai dengan yang diharapkan oleh result.html
    # Kita harus memetakan nama kolom database (kecil) ke nama tampilan (Kapital)
    input_data = {
        'Pregnancies': record.pregnancies,
        'Glucose': record.glucose,
        'BloodPressure': record.blood_pressure,
        'SkinThickness': record.skin_thickness,
        'Insulin': record.insulin,
        'BMI': record.bmi,
        'DiabetesPedigreeFunction': record.dpf,
        'Age': record.age
    }

    # 4. Render halaman hasil (result.html) dengan data dari database
    return render_template(
        'result.html',
        prediction=record.prediction_class,
        probability=f"{record.probability:.2f}%",
        probability_raw=record.probability,
        risk_level=record.risk_level,
        input_data=input_data
    )

if __name__ == "__main__":
    with app.app_context():
        print("Mencoba membuat tabel di database MySQL...")
        db.create_all() # Akan membuat tabel User dan PredictionHistory
        print("Inisialisasi database selesai.")
    app.run(debug=True)