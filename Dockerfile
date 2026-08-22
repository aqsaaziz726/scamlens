# Start from a small Python image
FROM python:3.12-slim

# Install Tesseract OCR (the system program, not just the Python wrapper)
RUN apt-get update && \
    apt-get install -y tesseract-ocr && \
    rm -rf /var/lib/apt/lists/*

# Set the working folder inside the container
WORKDIR /app

# Copy just the requirements first (speeds up future rebuilds)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the project files
COPY . .

# Render (and most hosts) tell us which port to listen on via $PORT
ENV PORT=10000
EXPOSE 10000

# Run with gunicorn (production server) instead of Flask's dev server
CMD gunicorn --bind 0.0.0.0:$PORT app:app