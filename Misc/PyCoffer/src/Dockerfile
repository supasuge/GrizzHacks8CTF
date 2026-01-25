FROM python:3.14 as builder

RUN apt-get update -y && \
    apt-get upgrade -y && \ 
    apt-get install python3-pip libssl-dev python3-dev socat supervisor -y

WORKDIR /app
COPY sandbox.py .
COPY flag.txt .
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
EXPOSE 1337

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
