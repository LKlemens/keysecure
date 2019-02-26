CXX = g++
CXXFLAGS =  -Wall -Wextra  -std=c++11 -c
LINKING_FLAGS = -L. -lkeysecure -lcrypto -lgtest -lpthread
EXECUTABLE = test

all: ${EXECUTABLE}

${EXECUTABLE}: TestKeysecure.o libkeysecure.a
	${CXX} TestKeysecure.o ${LINKING_FLAGS} -o ${EXECUTABLE}

keysecure.o: ../src/keysecure.cpp ../src/keysecure.hpp
	${CXX} ${CXXFLAGS} -DTEST $<

libkeysecure.a: keysecure.o
	ar crs $@ $^
	ranlib $@

TestKeysecure.o: TestKeysecure.cpp
	${CXX} -I../src/ ${CXXFLAGS} $<

run:
	./${EXECUTABLE}

clean:
	-rm -rf ${EXECUTABLE} keysecure.o libkeysecure.a TestKeysecure.o a.out

.PHONY: all clean run
