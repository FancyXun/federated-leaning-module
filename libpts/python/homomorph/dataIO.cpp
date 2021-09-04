#include <pybind11/pybind11.h>
#include <pybind11/eigen.h>
#include <pybind11/stl.h>
#include <gmp.h>
#include "dataIO.h"

namespace py = pybind11;


py::array_t<uint8_t> export_fixed_size_array(mpz_t t, int fixed_size)
{
    py::array_t<uint8_t> result = py::array_t<uint8_t>(fixed_size);
    py::buffer_info buf = result.request();
    uint8_t *ptr = static_cast<uint8_t *>(buf.ptr);
    // the workaround is set last 3-5 index to zero
    // todo: find numpy array initialization
    ptr[fixed_size-1] = 0;
    ptr[fixed_size-2] = 0;
    ptr[fixed_size-3] = 0;
    ptr[fixed_size-4] = 0;
    ptr[fixed_size-5] = 0;
    mpz_export(ptr, NULL, -1, 1, 1, 0, t);
    return result;
}


void mpz_import_uint8_array_t(mpz_t t, py::list pk_vk, int index)
{
    py::array_t<uint8_t> casted_array = py::cast<py::array>(pk_vk[index]);
    auto requestCastedArray = casted_array.request();
    uint8_t* ptrArray = (uint8_t*) requestCastedArray.ptr;
    mpz_import(t, requestCastedArray.shape[0], -1, 1, 1, 0, ptrArray);
}