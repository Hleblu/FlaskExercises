FROM python:3.10
EXPOSE 5000
WORKDIR /app
RUN pip install flask flask_restful
COPY . .
CMD ["flask", "run", "--host", "0.0.0.0"]