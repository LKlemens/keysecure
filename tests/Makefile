CC = g++
FLAGS =  -Wall -Wextra  -std=c++11 -c
LINKING_FLAGS = -L. -lkeysecure -lcrypto -lgtest -lpthread
EXECUTABLE = test

all: ${EXECUTABLE}

${EXECUTABLE}: TestKeysecure.o libkeysecure.a
	${CC} TestKeysecure.o ${LINKING_FLAGS} -o ${EXECUTABLE}

keysecure.o: ../src/keysecure.cpp ../src/keysecure.hpp
	${CC} ${FLAGS} -DTEST $<

libkeysecure.a: keysecure.o
	ar crs $@ $^
	ranlib $@

TestKeysecure.o: TestKeysecure.cpp
	${CC} -I../src/ ${FLAGS} $<

run:
	./${EXECUTABLE}

clean:
	-rm -rf ${EXECUTABLE} keysecure.o libkeysecure.a TestKeysecure.o a.out

.PHONY = all clean run

