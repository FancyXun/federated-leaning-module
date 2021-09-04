#include <gmp.h>    // gmp is included implicitly
#include <libhcs.h> // master header includes everything
#include <pybind11/eigen.h>
#include <pybind11/stl.h>
#include <Eigen/Dense>
#include <gmpxx.h>

#ifdef __cplusplus
extern "C" {
#endif

namespace py = pybind11;

std::vector<py::array_t<uint8_t >> paillier_encrypt(py::array_t<long long> plain,
                                                    py::list pk_list_of_arr, int parallel);

std::vector<Eigen::MatrixXd> paillier_generate_key_pair_mat(Eigen::Ref<const Eigen::MatrixXd> pk_mat,
                                                            Eigen::Ref<const Eigen::VectorXd> vk_mat, int key_size);

#ifdef __cplusplus
}
#endif
