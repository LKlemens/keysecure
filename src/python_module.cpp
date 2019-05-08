#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "keysecure.hpp"

namespace py = pybind11;

PYBIND11_MODULE(keysecure, m) {
  py::class_<kfp::Keysecure>(m, "Keysecure")
      .def(py::init<std::string, std::string, std::string>())
      .def("get_db", &kfp::Keysecure::get_db)
      .def("save_entry", &kfp::Keysecure::save_entry)
      // .def("get_entry", &kfp::Keysecure::get_entry)
      .def("delete_entry", &kfp::Keysecure::delete_entry);
}
