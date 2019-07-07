CXX := g++
CXXFLAGS := -g -Wall -Wextra -std=c++11 -lbotan-2 -I/usr/include/botan-2
PY_LIBS != python3 -m pybind11  --includes

all: keysecure.o libkeysecure.a keysecure.cpython-37m-x86_64-linux-gnu.so

libkeysecure.a: keysecure.o
	ar crs $@ $^
	ranlib $@

keysecure.o: src/keysecure.cpp src/keysecure.hpp
	${CXX} ${CXXFLAGS} -c $<

keysecure.cpython-37m-x86_64-linux-gnu.so: src/python_module.cpp src/keysecure.cpp src/keysecure.hpp
	${CXX} ${CXXFLAGS} -shared -fPIC ${PY_LIBS} src/keysecure.cpp -lbotan-2 -I/usr/include/botan-2 $< -o keysecure`python3-config --extension-suffix`


clean:
	-rm -rf libkeysecure.a keysecure.o keysecure.cpython-37m-x86_64-linux-gnu.so a.out

.PHONY: all clean
