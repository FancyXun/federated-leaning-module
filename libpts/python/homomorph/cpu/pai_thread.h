#include <pybind11/pybind11.h>
#include <pybind11/eigen.h>
#include <pybind11/stl.h>
#include <libhcs.h>

namespace py = pybind11;

namespace cpu
{
    namespace optimization
    {
        std::vector<py::array_t<uint8_t>> batch_encrypt(pcs_public_key* pk, hcs_random *hr, int cipher_size,
                                                        py::array_t<long long> plain, int parallel);
    }
}
