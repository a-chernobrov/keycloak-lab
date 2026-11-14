# build context = корень lab/ (см. docker-compose.yml)
FROM python:3.12-slim
WORKDIR /app
COPY vuln-rs/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY vuln-rs/app.py .
COPY scripts/jwks.py .
EXPOSE 8090
CMD ["gunicorn", "-b", "0.0.0.0:8090", "-w", "2", "app:app"]