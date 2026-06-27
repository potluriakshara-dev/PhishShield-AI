# Use a slim official Python base image
FROM python:3.10-slim

# Install system dependencies needed for OpenCV and pyzbar (QR decoding)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1 \
    libglib2.0-0 \
    libzbar0 \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file and install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application files into the container
COPY . .

# Set default port to 5001 (Render/Railway will override this automatically)
ENV PORT=5001

# Command to run the application using gunicorn production server
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:$PORT web_server:app"]
