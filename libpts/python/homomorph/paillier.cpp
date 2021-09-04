#include <time.h>
#include <pybind11/pybind11.h>
#include <pybind11/eigen.h>
#include <pybind11/stl.h>
#include <Eigen/Dense>
#include "cpu/paillier_thread.h"
#include "dataIO.h"

#ifdef __cplusplus
#include"paillier.h"
extern "C"{
#endif

namespace py = pybind11;


std::vector<py::array_t<uint8_t >> paillier_generate_key_pair(int key_size)
{
    std::vector<py::array_t<uint8_t >> matrices;
    // initialize data structures
    pcs_public_key *pk = pcs_init_public_key();
    pcs_private_key *vk = pcs_init_private_key();
    hcs_random *hr = hcs_init_random();
    pcs_generate_key_pair(pk, vk, hr, key_size);
    auto pk_n = array_t_initialize(pk->n, 256);
    auto pk_g = array_t_initialize(pk->g, 256);
    auto pk_n2 = array_t_initialize(pk->n2, 256);
    auto pk_maxInt = array_t_initialize(pk->maxInt, 256);
    auto vk_p = array_t_initialize(vk->p, 256);
    auto vk_q = array_t_initialize(vk->q, 256);
    auto vk_p2 = array_t_initialize(vk->p2, 256);
    auto vk_q2 = array_t_initialize(vk->q2, 256);
    auto vk_hp = array_t_initialize(vk->hp, 256);
    auto vk_hq = array_t_initialize(vk->hq, 256);
    auto vk_lambda = array_t_initialize(vk->lambda, 256);
    auto vk_mu = array_t_initialize(vk->mu, 256);
    auto vk_n = array_t_initialize(vk->n, 256);
    auto vk_n2 = array_t_initialize(vk->n2, 256);
    auto vk_maxInt = array_t_initialize(vk->maxInt, 256);

    #pragma omp parallel sections
    {
        #pragma omp section
        {
            pk_n = mpz_export_array_t(pk_n, pk->n, 0);
            pk_g = mpz_export_array_t(pk_g, pk->g, 0);
            pk_n2 = mpz_export_array_t(pk_n2, pk->n2, 0);
            pk_maxInt = mpz_export_array_t(pk_maxInt, pk->maxInt, 0);
        }
        #pragma omp section
        {
            vk_p = mpz_export_array_t(vk_p, vk->p, 0);
            vk_q = mpz_export_array_t(vk_q, vk->q, 0);
            vk_p2 = mpz_export_array_t(vk_p2, vk->p2, 0);
            vk_q2 = mpz_export_array_t(vk_q2, vk->q2, 0);
            vk_hp = mpz_export_array_t(vk_hp, vk->hp, 0);
            vk_hq = mpz_export_array_t(vk_hq, vk->hq, 0);
            vk_lambda = mpz_export_array_t(vk_lambda, vk->lambda, 0);
            vk_mu = mpz_export_array_t(vk_mu, vk->mu, 0);
            vk_n = mpz_export_array_t(vk_n, vk->n, 0);
            vk_n2 = mpz_export_array_t(vk_n2, vk->n2, 0);
            vk_maxInt = mpz_export_array_t(vk_maxInt, vk->maxInt, 0);
        }
    }
    matrices.push_back(pk_n);
    matrices.push_back(pk_g);
    matrices.push_back(pk_n2);
    matrices.push_back(pk_maxInt);
    matrices.push_back(vk_p);
    matrices.push_back(vk_q);
    matrices.push_back(vk_p2);
    matrices.push_back(vk_q2);
    matrices.push_back(vk_hp);
    matrices.push_back(vk_hq);
    matrices.push_back(vk_lambda);
    matrices.push_back(vk_mu);
    matrices.push_back(vk_n);
    matrices.push_back(vk_n2);
    matrices.push_back(vk_maxInt);
    return matrices;

}


void pk_vk_reconstruct(pcs_public_key *pk, pcs_private_key *vk, py::list pk_vk)
{
    #pragma omp parallel sections
    {
        #pragma omp section
        {
            mpz_import_uint8_array_t(pk->n, pk_vk, 0);
            mpz_import_uint8_array_t(pk->g, pk_vk, 1);
            mpz_import_uint8_array_t(pk->n2, pk_vk, 2);
            mpz_import_uint8_array_t(pk->maxInt, pk_vk, 3);
        }
        #pragma omp section
        {
            mpz_import_uint8_array_t(vk->p, pk_vk, 4);
            mpz_import_uint8_array_t(vk->q, pk_vk, 5);
            mpz_import_uint8_array_t(vk->p2, pk_vk, 6);
            mpz_import_uint8_array_t(vk->q2, pk_vk, 7);
            mpz_import_uint8_array_t(vk->hp, pk_vk, 8);
            mpz_import_uint8_array_t(vk->hq, pk_vk, 9);
            mpz_import_uint8_array_t(vk->lambda, pk_vk, 10);
            mpz_import_uint8_array_t(vk->mu, pk_vk, 11);
            mpz_import_uint8_array_t(vk->n, pk_vk, 12);
            mpz_import_uint8_array_t(vk->n2, pk_vk, 13);
            mpz_import_uint8_array_t(vk->maxInt, pk_vk, 14);
        }
    }
}

void pk_reconstruct(pcs_public_key *pk, py::list pk_list_of_arr)
{
    mpz_import_uint8_array_t(pk->n, pk_list_of_arr, 0);
    mpz_import_uint8_array_t(pk->g, pk_list_of_arr, 1);
    mpz_import_uint8_array_t(pk->n2, pk_list_of_arr, 2);
    mpz_import_uint8_array_t(pk->maxInt, pk_list_of_arr, 3);
}


std::vector<py::array_t<uint8_t >> paillier_batch_encrypt(py::array_t<long long> plain,
                                                          py::list pk_list_of_arr, int parallel)
{

    std::vector<py::array_t<uint8_t >> matrices;
    pcs_public_key *pk = pcs_init_public_key();
    hcs_random *hr = hcs_init_random();
    pk_reconstruct(pk, pk_list_of_arr);
    int cipher_size = mpz_sizeinbase(pk->n, 256)*2+1;
    switch (parallel)
    {
        case 1:
            {
                mpz_t a;
                py::buffer_info buf = plain.request();
                if (buf.ndim != 1)
                    throw std::runtime_error("Number of dimensions must be one");
                long long *ptr = (long long *) buf.ptr;
                for(long long i = 0; i < buf.shape[0]; i++)
                {
                    mpz_init_set_str(a, std::to_string(ptr[i]).c_str(), 10);
                    pcs_encrypt(pk, hr, a, a);
                    // todo: decrease cipher_size
                    auto a_arr = array_t_initialize_fixed_size(a, cipher_size);
                    a_arr = mpz_export_array_t(a_arr, a, cipher_size);
                    matrices.push_back(a_arr);
                }
            }
            break;
        default:
            matrices = inner_batch_encrypt(pk, hr, cipher_size, plain, parallel);
    }
    return matrices;
}

py::array_t<uint8_t> paillier_sum(py::list pk_list_of_arr, py::list cipher_list_of_arr)
{
    pcs_public_key *pk = pcs_init_public_key();
    hcs_random *hr = hcs_init_random();
    pk_reconstruct(pk, pk_list_of_arr);
    mpz_t a, cipher_sum;
    mpz_inits(cipher_sum, a, NULL);
    mpz_set_ui(cipher_sum, 0);
    pcs_encrypt(pk, hr, cipher_sum, cipher_sum);
    for(py::handle array: cipher_list_of_arr)
    {
        py::array_t<uint8_t> casted_array = py::cast<py::array>(array);
        auto requestCastedArray = casted_array.request();
        uint8_t* ptrArray = (uint8_t*) requestCastedArray.ptr;
        mpz_import(a, requestCastedArray.shape[0], -1, 1, 1, 0, ptrArray);
        pcs_ee_add(pk, cipher_sum, a, cipher_sum);
    }
    auto cipher_sum_auto = array_t_initialize(cipher_sum, 256);
    cipher_sum_auto = mpz_export_array_t(cipher_sum_auto, cipher_sum, 0);
    py::array_t<uint8_t> cipher_sum_uint8_t = py::cast<py::array>(cipher_sum_auto);
    return cipher_sum_uint8_t;
}

char* paillier_decrypt(py::list pk_vk_list_of_arr, py::array_t<uint8_t> cipher_arr)
{
    mpz_t a;
    mpz_inits(a, NULL);

    pcs_public_key *pk = pcs_init_public_key();
    pcs_private_key *vk = pcs_init_private_key();
    pk_vk_reconstruct(pk, vk, pk_vk_list_of_arr);

    auto requestCastedArray = cipher_arr.request();
    uint8_t* ptrArray = (uint8_t*) requestCastedArray.ptr;
    mpz_import(a, requestCastedArray.shape[0], -1, 1, 1, 0, ptrArray);
    pcs_decrypt(vk, a, a);
    char *char_arr = mpz_get_str(NULL, 10, a);

    return char_arr;
}

py::list paillier_batch_decrypt(py::list pk_vk_list_of_arr, py::list cipher_list_of_arr, int parallel)
{
    pcs_public_key *pk = pcs_init_public_key();
    pcs_private_key *vk = pcs_init_private_key();
    pk_vk_reconstruct(pk, vk, pk_vk_list_of_arr);
    return inner_batch_decrypt(pk, vk, cipher_list_of_arr, parallel);
}

py::list paillier_batch_mul(py::list pk_list_of_arr, py::list cipher_list_of_arr, py::list plain, int parallel)
{
    pcs_public_key *pk = pcs_init_public_key();
    pk_reconstruct(pk, pk_list_of_arr);
    int cipher_size = mpz_sizeinbase(pk->n, 256)*2+1;
    return inner_batch_mul(pk, cipher_list_of_arr, plain, parallel, cipher_size);
}

void paillier_mul(py::list pk_list_of_arr, py::array_t<uint8_t> cipher_arr)
{

}


PYBIND11_MODULE(libpts, m)
{
    m.def("paillier_generate_key_pair", &paillier_generate_key_pair);
    m.def("paillier_batch_encrypt", &paillier_batch_encrypt);
    m.def("paillier_sum", &paillier_sum);
    m.def("paillier_decrypt", &paillier_decrypt);
    m.def("paillier_batch_decrypt", &paillier_batch_decrypt);
    m.def("paillier_batch_mul", &paillier_batch_mul);
    m.def("paillier_mul", &paillier_mul);
}

#ifdef __cplusplus
}
#endif
