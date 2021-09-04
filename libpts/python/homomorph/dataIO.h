#include <pybind11/pybind11.h>
#include <pybind11/eigen.h>
#include <pybind11/stl.h>
#include <gmp.h>

namespace py = pybind11;

inline auto mpz_export_array_t(auto result, mpz_t t, int cipher_size)
{
    py::buffer_info buf = result.request();
    uint8_t *ptr = static_cast<uint8_t *>(buf.ptr);
    // the workaround is set last 3-5 index to zero
    // todo: find numpy array initialization
    if (cipher_size > 0)
    {
        ptr[cipher_size-1] = 0;
        ptr[cipher_size-2] = 0;
        ptr[cipher_size-3] = 0;
        ptr[cipher_size-4] = 0;
        ptr[cipher_size-5] = 0;
    }
    mpz_export(ptr, NULL, -1, 1, 1, 0, t);
    return result;
}


inline auto array_t_initialize(mpz_t t, int array_type)
{
    int size = mpz_sizeinbase(t, array_type);
    auto result = py::array_t<uint8_t>(size);
    return result;
}

inline auto array_t_initialize_fixed_size(mpz_t t, int fixed_size)
{
    auto result = py::array_t<uint8_t>(fixed_size);
    return result;
}

py::array_t<uint8_t> export_fixed_size_array(mpz_t t, int fixed_size);

void mpz_import_uint8_array_t(mpz_t t, py::list pk_vk, int index);


