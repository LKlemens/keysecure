CXX = g++
CXXFLAGS =  -Wall -Wextra  -std=c++11 -c
OBJ = keysecure.o
KEY_LIB = libkeysecure.a

all: ${OBJ} ${KEY_LIB}

libkeysecure.a: ${OBJ}
	ar crs ${KEY_LIB} ${OBJ}
	ranlib ${KEY_LIB}

keysecure.o: src/keysecure.cpp src/keysecure.hpp
	${CXX} ${CXXFLAGS} $<

clean:
	-rm -rf ${KEY_LIB} ${OBJ} a.out

.PHONY = all clean

