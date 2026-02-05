FROM python:3.12-slim

WORKDIR /app

COPY app.py /app/app.py

EXPOSE 3000

ENV LISTEN_HOST=0.0.0.0 \
    LISTEN_PORT=3000

CMD ["python", "-u", "app.py"]
