from flask import Flask, render_template, request
import numpy as np
import pickle

app = Flask(__name__)

# Load model & scaler
model = pickle.load(open('model/diabetes_model.pkl', 'rb'))
scaler = pickle.load(open('model/scaler.pkl', 'rb'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
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
        final_input = np.array([inputs])
        scaled_input = scaler.transform(final_input)
        prediction = model.predict(scaled_input)[0]

        result_text = "⚠️ Anda berisiko diabetes" if prediction == 1 else "✅ Anda tidak berisiko diabetes"
        return render_template('result.html', result=result_text)
    except Exception as e:
        return render_template('result.html', result=f"Terjadi kesalahan: {e}")

if __name__ == "__main__":
    app.run(debug=True)
