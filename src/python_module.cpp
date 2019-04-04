#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "keysecure.hpp"

namespace py = pybind11;

PYBIND11_MODULE(keysecure, m) {
  py::class_<kfp::Keysecure>(m, "Keysecure")
      .def(py::init<std::string, std::string>())
      .def("read_from_db", &kfp::Keysecure::read_from_db)
      .def("write_to_db", &kfp::Keysecure::write_to_db);
}
