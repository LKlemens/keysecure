FROM alpine:3.7 AS dev

WORKDIR /home/keysecure

RUN apk add g++ gtest gtest-dev cmake make git vim pytest python3 python3-dev gdb

RUN git clone https://github.com/pybind/pybind11.git && \
	cd pybind11 && \
	mkdir build && \
	cd build && \
	cmake .. && \
	make check -j 4 && \
  python3 -m pip install pybind11 && \
	ln -s /home/keysecure/pybind11/include/pybind11 /usr/local/include

RUN  git clone https://github.com/randombit/botan.git && \
	cd botan && \
	./configure.py && \
	make && \
	make install && \
	ln -s /home/keysecure/botan/build/include/botan /usr/local/include


COPY . /home/keysecure

