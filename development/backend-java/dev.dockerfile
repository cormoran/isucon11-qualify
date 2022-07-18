FROM openjdk:17.0.2-buster
WORKDIR /webapp/java

#install mariadb-client
RUN apt-get update \
    && apt-get install -y default-mysql-client

ENV DOCKERIZE_VERSION v0.6.1
RUN wget https://github.com/jwilder/dockerize/releases/download/$DOCKERIZE_VERSION/dockerize-alpine-linux-amd64-$DOCKERIZE_VERSION.tar.gz \
    && tar -C /usr/local/bin -xzvf dockerize-alpine-linux-amd64-$DOCKERIZE_VERSION.tar.gz \
    && rm dockerize-alpine-linux-amd64-$DOCKERIZE_VERSION.tar.gz

RUN ln -sf /usr/share/zoneinfo/Asia/Tokyo /etc/localtime

