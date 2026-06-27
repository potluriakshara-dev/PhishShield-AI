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

# Command to run the Tkinter-based desktop application
CMD ["python", "main.py"]
