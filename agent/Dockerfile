FROM python:3.12-slim

WORKDIR /app

COPY shared/ /shared/
RUN pip install --no-cache-dir /shared/

COPY agent/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent/ .

ENTRYPOINT ["python", "scan.py"]
