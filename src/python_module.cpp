#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "keysecure.hpp"

namespace py = pybind11;

PYBIND11_MODULE(keysecure, m) {
  py::class_<kfp::Keysecure>(m, "Keysecure")
      .def(py::init<std::string, std::string, const char*>())
      .def("get_db", &kfp::Keysecure::get_db)
      .def("add_entry", &kfp::Keysecure::add_entry)
      .def("delete_entry", &kfp::Keysecure::delete_entry);
}
