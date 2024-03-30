FROM ubuntu:latest
LABEL authors="Vishal"

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip\
    php-cgi \
    net-tools \
    python3-magic \
    tzdata

RUN echo $TZ > /etc/timezone && \
    rm /etc/localtime && \
    ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata

COPY Code /app

RUN pip3 install selenium pytz

WORKDIR /app

CMD ["python3", "server.py", "0.0.0.0", "4000"]
