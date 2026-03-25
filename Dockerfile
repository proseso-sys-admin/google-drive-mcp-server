FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
# Install from lock file for reproducible builds
COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock

COPY main.py .

ENV PORT=8080

CMD ["python", "main.py"]
