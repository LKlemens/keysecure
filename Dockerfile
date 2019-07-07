FROM alpine:3.7 AS dev

WORKDIR /home/keysecure

RUN apk add g++ openssl openssl-dev gtest gtest-dev cmake make git vim pytest python3 python3-dev gdb

RUN git clone https://github.com/pybind/pybind11.git && \
	cd pybind11 && \
	mkdir build && \
	cd build && \
	cmake .. && \
	make check -j 4

COPY . /home/keysecure

