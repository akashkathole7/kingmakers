# Use Python 3.9 slim base image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV PORT=5000

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Create necessary directories
RUN mkdir -p logs uploads

# Set permissions
RUN chmod -R 755 /app

# Expose the port the app runs on
EXPOSE $PORT

# Create a non-root user and switch to it
RUN useradd -m myuser
USER myuser

# Start the application with gunicorn
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:$PORT --workers 4 app:app"]