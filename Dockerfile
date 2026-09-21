FROM python:3.12-slim
WORKDIR /app
COPY password_checker.py .
RUN useradd -m app
USER app
ENTRYPOINT ["python", "password_checker.py"]
