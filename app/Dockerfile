FROM python:3.12-slim

WORKDIR /service
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pin_manager /service/pin_manager

EXPOSE 80
CMD ["uvicorn", "pin_manager.main:app", "--host", "0.0.0.0", "--port", "80"]
