# Gunakan image Python yang ringan
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Salin requirements dan install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Salin seluruh kode aplikasi
COPY . .

# Pastikan folder model ikut terbawa (sesuaikan path folder jika perlu)
# Di kode Anda folder model bernama 'model'
COPY model/ model/

# Expose port (Cloud Run secara default menggunakan port 8080)
ENV PORT 8080

# Jalankan aplikasi menggunakan Gunicorn
# app:app artinya file app.py, variabel app
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 app:app