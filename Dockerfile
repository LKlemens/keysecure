FROM alpine:3.7 AS dev

WORKDIR /home/keysecure

RUN apk add g++ openssl openssl-dev gtest gtest-dev make vim

COPY . /home/keysecure
