CXX := g++
CXXFLAGS :=  -O3 -Wall -Wextra -std=c++11
OBJ := keysecure.o
KEY_LIB := libkeysecure.a
PY_LIBS != python3 -m pybind11  --includes

all: ${OBJ} ${KEY_LIB} keysecure.cpython-37m-x86_64-linux-gnu.so

libkeysecure.a: ${OBJ}
	ar crs ${KEY_LIB} ${OBJ}
	ranlib ${KEY_LIB}

keysecure.o: src/keysecure.cpp src/keysecure.hpp
	${CXX} ${CXXFLAGS} -c $<

keysecure.cpython-37m-x86_64-linux-gnu.so: src/python_module.cpp src/keysecure.cpp src/keysecure.hpp
	${CXX} ${CXXFLAGS} -shared -fPIC -lcrypto ${PY_LIBS} src/keysecure.cpp $< -o keysecure`python3-config --extension-suffix`


clean:
	-rm -rf ${KEY_LIB} ${OBJ} keysecure.cpython-37m-x86_64-linux-gnu.so a.out

.PHONY: all clean
