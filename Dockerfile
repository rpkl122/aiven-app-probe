FROM python:3.12-alpine
WORKDIR /app
COPY server.py ctfprobe.py .
EXPOSE 8080
CMD ["python", "ctfprobe.py"]
