#include <gmp.h>    // gmp is included implicitly
#include <libhcs.h> // master header includes everything
#include <gmpxx.h>
#include <pybind11/pybind11.h>
#include <pybind11/eigen.h>
#include <pybind11/stl.h>

namespace py = pybind11;


std::vector<py::array_t<uint8_t>> inner_batch_encrypt(pcs_public_key* pk, hcs_random *hr, int cipher_size,
                                                py::array_t<long long> plain, int parallel);

py::list inner_batch_decrypt(pcs_public_key *pk, pcs_private_key *vk, py::list cipher_list_of_arr, int parallel);

py::list inner_batch_mul(pcs_public_key *pk, py::list cipher_list_of_arr, py::list plain, int parallel, int cipher_size);