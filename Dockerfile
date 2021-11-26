FROM python:3.8

WORKDIR /app

ADD . .

RUN apt install libpq-dev

RUN pip install -r requirements.txt

EXPOSE 5000

ENTRYPOINT [ "sh", "./docker-entrypoint.sh" ]