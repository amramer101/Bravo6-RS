FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY . /app

EXPOSE 5001

CMD ["python", "validation-benchmark/app.py"]
