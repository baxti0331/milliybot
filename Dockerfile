FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Системные зависимости для OpenCV, pyzbar, Tesseract OCR, FFmpeg и Playwright
RUN apt-get update && apt-get install -y --no-install-recommends \
    libzbar0 \
    tesseract-ocr \
    ffmpeg \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Установка Chromium и его системных библиотек для кнопки «Скриншот сайта»
RUN playwright install --with-deps chromium

# Директория для постоянного хранения SQLite базы и сессий
RUN mkdir -p /data

COPY bot.py .

CMD ["python", "bot.py"]
