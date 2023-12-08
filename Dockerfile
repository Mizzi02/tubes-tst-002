FROM python:3.11
WORKDIR /
COPY . .
RUN pip install -r requirements.txt
EXPOSE 5500
CMD ["python", "main.py"]