FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --upgrade pip

RUN pip install --no-cache-dir -r requirements.txt

COPY orm_helpers.py .

COPY parse_log.py .

CMD python parse_log.py

