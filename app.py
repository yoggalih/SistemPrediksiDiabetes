import os
import requests
import json
import numpy as np
import pickle
from datetime import datetime, timedelta
from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, redirect, url_for, session, abort, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

# --- Konfigurasi dan Inisialisasi ---
app = Flask(__name__)

# Database
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///database.db') 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Secret Key
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'kunci_rahasia_default_jika_env_hilang')

# reCAPTCHA
app.config['RECAPTCHA_SITE_KEY'] = os.getenv('RECAPTCHA_SITE_KEY')
app.config['RECAPTCHA_SECRET_KEY'] = os.getenv('RECAPTCHA_SECRET_KEY')

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'check_diabetes_page' 
login_manager.login_message = "Silakan login terlebih dahulu untuk mengakses halaman ini."

# Load model & scaler
try:
    model = pickle.load(open('model/diabetes_model.pkl', 'rb'))
    scaler = pickle.load(open('model/scaler.pkl', 'rb'))
except FileNotFoundError:
    print("WARNING: Model/Scaler files not found. Prediction routes might fail.")
    model = None
    scaler = None

# --- MODEL DATABASE USER & HISTORY ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(512), nullable=False)
    predictions = db.relationship('PredictionHistory', backref='predictor', lazy='dynamic')

    def __init__(self, username, password_hash):
        self.username = username
        self.password_hash = password_hash

class PredictionHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    prediction_date = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=7))
    
    # Data Input
    pregnancies = db.Column(db.Float, nullable=False)
    glucose = db.Column(db.Float, nullable=False)
    blood_pressure = db.Column(db.Float, nullable=False)
    skin_thickness = db.Column(db.Float, nullable=False)
    insulin = db.Column(db.Float, nullable=False)
    bmi = db.Column(db.Float, nullable=False)
    dpf = db.Column(db.Float, nullable=False)
    age = db.Column(db.Float, nullable=False)
    
    # Data Hasil
    prediction_class = db.Column(db.Integer, nullable=False)
    probability = db.Column(db.Float, nullable=False)
    risk_level = db.Column(db.String(50), nullable=False)
    
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# --- Fungsi Helper & Logika Bisnis ---

def verify_recaptcha(response_token):
    """Verifikasi reCAPTCHA."""
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

def generate_health_advice(inputs):
    """
    [FITUR BARU]
    Menghasilkan list saran kesehatan personal berdasarkan nilai input.
    """
    advice = []
    
    # 1. Cek BMI (Berat Badan)
    bmi = inputs.get('BMI', 0)
    if bmi > 30:
        advice.append({
            'type': 'danger', 
            'icon': 'fa-weight-scale',
            'title': 'Indeks Massa Tubuh (Obesitas)',
            'text': 'BMI Anda menunjukkan obesitas. Fokus utama adalah penurunan berat badan bertahap melalui defisit kalori dan olahraga kardio (jalan cepat/berenang).'
        })
    elif bmi > 25:
        advice.append({
            'type': 'warning',
            'icon': 'fa-weight-scale',
            'title': 'Indeks Massa Tubuh (Overweight)',
            'text': 'Berat badan Anda berlebih. Disarankan mengurangi makanan berlemak/gorengan dan rutin bergerak minimal 30 menit sehari.'
        })
        
    # 2. Cek Glukosa
    glucose = inputs.get('Glucose', 0)
    if glucose > 200:
        advice.append({
            'type': 'danger',
            'icon': 'fa-droplet',
            'title': 'Kadar Gula Darah Sangat Tinggi',
            'text': 'Kadar gula Anda sangat tinggi. Segera konsultasikan ke dokter untuk pemeriksaan HbA1c dan kemungkinan terapi obat.'
        })
    elif glucose > 140:
        advice.append({
            'type': 'warning',
            'icon': 'fa-droplet',
            'title': 'Kadar Gula Darah Tinggi',
            'text': 'Kurangi konsumsi gula sederhana (sirup, minuman manis, kue) dan ganti karbohidrat putih dengan karbohidrat kompleks (beras merah/gandum).'
        })

    # 3. Cek Tekanan Darah (Diastolik)
    bp = inputs.get('BloodPressure', 0)
    if bp > 90:
        advice.append({
            'type': 'warning',
            'icon': 'fa-heart-pulse',
            'title': 'Tekanan Darah (Diastolik Tinggi)',
            'text': 'Waspada hipertensi. Kurangi asupan garam (natrium) dan hindari makanan olahan/kalengan. Kelola stres dengan baik.'
        })

    # 4. Cek Umur
    age = inputs.get('Age', 0)
    if age > 45:
        advice.append({
            'type': 'info',
            'icon': 'fa-calendar-check',
            'title': 'Faktor Usia',
            'text': 'Di usia >45 tahun, metabolisme melambat. Penting untuk melakukan check-up rutin (gula darah, kolesterol) minimal 6 bulan sekali.'
        })

    # Jika tidak ada masalah spesifik
    if not advice:
        advice.append({
            'type': 'success',
            'icon': 'fa-check-circle',
            'title': 'Kondisi Parameter Baik',
            'text': 'Parameter kesehatan Anda terlihat dalam batas wajar. Pertahankan gaya hidup sehat, pola makan seimbang, dan olahraga rutin Anda!'
        })
        
    return advice


# --- Route Authentication ---

@app.route('/login', methods=['POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('check_diabetes_page'))

    username = request.form.get('username')
    password = request.form.get('password')
    recaptcha_token = request.form.get('g-recaptcha-response')
    
    if not recaptcha_token or not verify_recaptcha(recaptcha_token):
        flash('Verifikasi CAPTCHA gagal. Silakan coba lagi.', 'danger')
        return redirect(url_for('check_diabetes_page'))

    user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()
    
    if user and check_password_hash(user.password_hash, password):
        login_user(user)
        flash('Login berhasil! Selamat datang.', 'success')
        return redirect(url_for('check_diabetes_page'))
    else:
        flash('Username atau password salah.', 'danger')
        return redirect(url_for('check_diabetes_page'))


@app.route('/register', methods=['POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('check_diabetes_page'))

    username = request.form.get('username')
    password = request.form.get('password')
    recaptcha_token = request.form.get('g-recaptcha-response')

    if not recaptcha_token or not verify_recaptcha(recaptcha_token):
        flash('Verifikasi CAPTCHA gagal.', 'danger')
        return redirect(url_for('check_diabetes_page'))

    existing_user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()
    if existing_user:
        flash('Username sudah digunakan. Pilih yang lain.', 'warning')
        return redirect(url_for('check_diabetes_page'))

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password_hash=hashed_password) 

    db.session.add(new_user)
    db.session.commit()

    login_user(new_user)
    flash('Registrasi berhasil! Akun Anda telah dibuat.', 'success')
    return redirect(url_for('check_diabetes_page'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Anda telah logout.', 'info')
    return redirect(url_for('education'))


# --- Route Aplikasi Utama ---

@app.route('/')
@app.route('/education')
def education(): 
    return render_template('education.html', current_user=current_user)

@app.route('/check')
def check_diabetes_page():
    return render_template('index.html', current_user=current_user, site_key=app.config['RECAPTCHA_SITE_KEY']) 

@app.route('/history')
@login_required 
def prediction_history_page():
    history_records = db.session.execute(
        db.select(PredictionHistory)
        .filter_by(user_id=current_user.id)
        .order_by(PredictionHistory.prediction_date.desc())
    ).scalars().all()

    records_for_chart = history_records[::-1]

    dates = [rec.prediction_date.strftime('%d-%b-%Y') for rec in records_for_chart]
    probs = [rec.probability for rec in records_for_chart]
    glucose = [rec.glucose for rec in records_for_chart]

    return render_template(
        'history.html', 
        history=history_records, 
        current_user=current_user,
        chart_dates=json.dumps(dates),
        chart_probs=json.dumps(probs),
        chart_glucose=json.dumps(glucose)
    )

@app.route('/predict', methods=['POST'])
@login_required 
def predict():
    feature_names = ['Pregnancies', 'Glucose', 'BloodPressure', 'SkinThickness', 'Insulin', 'BMI', 'DiabetesPedigreeFunction', 'Age']

    default_context = {
        'prediction': 0,
        'probability': '0.00%',
        'probability_raw': 0.0,
        'risk_level': 'Tidak Diketahui',
        'input_data': {name: 'N/A' for name in feature_names},
        'advice_list': [] # Default kosong
    }

    try:
        input_values = {name: float(request.form[name]) for name in feature_names}
        
        # --- VALIDASI INPUT ---
        if any(value < 0 for value in input_values.values()):
             return render_template('result.html', result_error="Input tidak valid: Nilai tidak boleh negatif.", **default_context)
        if input_values['Glucose'] > 1000:
             return render_template('result.html', result_error="Input Glukosa tidak valid (>1000).", **default_context)
        if input_values['BloodPressure'] > 300:
             return render_template('result.html', result_error="Input Tensi tidak valid.", **default_context)
        if input_values['BMI'] > 100:
             return render_template('result.html', result_error="Input BMI tidak valid.", **default_context)
        if input_values['Age'] > 130 or input_values['Age'] < 1:
             return render_template('result.html', result_error="Input Usia tidak valid.", **default_context)
        if input_values['Insulin'] > 2000:
             return render_template('result.html', result_error="Input Insulin tidak valid.", **default_context)

        inputs = list(input_values.values())
        
        prediction = 0
        prediction_proba = 0.0
        risk_level = 'Tidak Diketahui'

        if model and scaler:
            final_input = np.array([inputs])
            scaled_input = scaler.transform(final_input)
            prediction = int(model.predict(scaled_input)[0])
            prediction_proba = model.predict_proba(scaled_input)[0][1] * 100 
            
            if prediction_proba >= 70: risk_level = "Sangat Tinggi"
            elif prediction_proba >= 50: risk_level = "Tinggi"
            elif prediction_proba >= 30: risk_level = "Sedang"
            else: risk_level = "Rendah"
        
        # --- GENERATE SARAN PERSONAL ---
        advice_list = generate_health_advice(input_values)

        wib_now = datetime.utcnow() + timedelta(hours=7)

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
            prediction_date=wib_now
        )
        db.session.add(new_history)
        db.session.commit()

        return render_template(
            'result.html', 
            prediction=prediction,       
            probability=f"{prediction_proba:.2f}%",  
            probability_raw=prediction_proba, 
            risk_level=risk_level,            
            input_data=input_values,
            advice_list=advice_list  # Kirim saran ke template
        )
            
    except ValueError:
        return render_template('result.html', result_error="Input tidak valid.", **default_context)
    except Exception as e:
        return render_template('result.html', result_error=f"Terjadi kesalahan: {e}", **default_context)

@app.route('/history/<int:prediction_id>')
@login_required
def prediction_detail(prediction_id):
    record = db.session.execute(
        db.select(PredictionHistory)
        .filter_by(id=prediction_id, user_id=current_user.id)
    ).scalar_one_or_none()

    if record is None:
        abort(404)

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
    
    # Generate saran untuk data historis juga
    advice_list = generate_health_advice(input_data)

    return render_template(
        'result.html',
        prediction=record.prediction_class,
        probability=f"{record.probability:.2f}%",
        probability_raw=record.probability,
        risk_level=record.risk_level,
        input_data=input_data,
        advice_list=advice_list # Kirim saran ke template
    )
    
@app.route('/history/delete/<int:prediction_id>', methods=['POST'])
@login_required
def delete_history(prediction_id):
    record = db.session.execute(
        db.select(PredictionHistory)
        .filter_by(id=prediction_id, user_id=current_user.id)
    ).scalar_one_or_none()

    if record:
        try:
            db.session.delete(record)
            db.session.commit()
            flash('Data riwayat berhasil dihapus.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Gagal menghapus data: {e}', 'danger')
    else:
        flash('Data tidak ditemukan.', 'danger')

    return redirect(url_for('prediction_history_page'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)