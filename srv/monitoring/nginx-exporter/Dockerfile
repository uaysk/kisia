FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY exporter.py ./

ENV LOG_PATH=/var/log/nginx/access.log
ENV LISTEN_PORT=9113

CMD ["python", "exporter.py"]
