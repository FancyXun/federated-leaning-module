#include <pybind11/pybind11.h>
#include <pybind11/eigen.h>
#include <pybind11/stl.h>
#include <gmp.h>    // gmp is included implicitly
#include <libhcs.h> // master header includes everything
#include <gmpxx.h>
#include "paillier_thread.h"
#include "../dataIO.h"

/*
 * It is only a temporary solution. The code of multithreading should have been separated from the main program,
 * but the program cannot run due to some unresolved bugs. Therefore, put this part of the code in the main
 * program first and the issue would be fixed in the future
 */

namespace py = pybind11;

struct cipherObject
{
    std::vector<long long> text;
    pcs_public_key *pk;
    hcs_random *hr;
    int cipher_size;
    std::vector<mpz_class> result;
};

struct plainObject
{
    pcs_public_key *pk;
    pcs_private_key *vk;
    std::vector<mpz_class> cipherText;
    std::vector<char*> result;
};

struct cipherMulObj
{
    pcs_public_key *pk;
    std::vector<mpz_class> cipherText;
    std::vector<mpz_class> text;
    std::vector<mpz_class> result;

};

static void* inner_encrypt(void *arguments)
{
    mpz_t a;
    struct cipherObject *cipher_object = (cipherObject *)arguments;
    for(long long i = 0; i<cipher_object->text.size(); ++i)
    {
        mpz_init_set_str(a, std::to_string(cipher_object->text[i]).c_str(), 10);
        pcs_encrypt(cipher_object->pk, cipher_object->hr, a, a);
        cipher_object->result.push_back(mpz_class(a));
    }
    mpz_clear(a);
}


static void* inner_decrypt(void *arguments)
{
    struct plainObject *plain_object = (plainObject *)arguments;
    mpz_t a;
    mpz_inits(a, NULL);
    for(long long i = 0; i<plain_object->cipherText.size(); ++i)
    {
        mpz_init_set_str(a, plain_object->cipherText[i].get_str().c_str(), 10);
        pcs_decrypt(plain_object->vk, a, a);
        char *char_arr = mpz_get_str(NULL, 10, a);
        plain_object->result.push_back(char_arr);
    }
    mpz_clear(a);
}

static void* inner_mul(void *arguments)
{
    struct cipherMulObj *cipher_mulObj = (cipherMulObj *)arguments;
    mpz_t a, b, c;
    mpz_inits(a, b, c, NULL);
    for(long long i = 0; i<cipher_mulObj->cipherText.size(); ++i)
    {
        mpz_init_set_str(a, cipher_mulObj->cipherText[i].get_str().c_str(), 10);
        mpz_init_set_str(b, cipher_mulObj->text[i].get_str().c_str(), 10);
        pcs_ep_mul(cipher_mulObj->pk, c, a, b);
        cipher_mulObj->result.push_back(mpz_class(c));
    }
    mpz_clear(a);
    mpz_clear(b);
    mpz_clear(c);
}

std::vector<py::array_t<uint8_t>> inner_batch_encrypt(pcs_public_key* pk, hcs_random *hr, int cipher_size,
                                                py::array_t<long long> plain, int parallel)
{
    py::buffer_info buf = plain.request();
    long long *ptr = (long long *) buf.ptr;
    long long per_parallel = buf.shape[0]/parallel;
    std::vector<cipherObject> cipherObjectVec(parallel);
    std::vector<py::array_t<uint8_t>> result;

    for(long long i = 0; i < parallel-1; i++)
    {
        struct cipherObject *cipher_object = new cipherObject;
        for (long long j=0; j<per_parallel; j++)
        {
            cipher_object->text.push_back(ptr[i*per_parallel+j]);
        }
        cipher_object->pk = pk;
        cipher_object->hr = hr;
        cipher_object->cipher_size = cipher_size;
        cipherObjectVec[i] = *cipher_object;
        delete cipher_object;
    }

    struct cipherObject *cipher_object = new cipherObject;
    for (long long j=(parallel-1)*per_parallel; j<buf.shape[0]; j++)
    {
        cipher_object->text.push_back(ptr[j]);
    }
    cipher_object->pk = pk;
    cipher_object->hr = hr;
    cipher_object->cipher_size = cipher_size;
    cipherObjectVec[parallel-1] = *cipher_object;
    delete cipher_object;


    pthread_t pt[parallel];
    for (auto i = 0; i < parallel; i++)
    {
        pthread_create(&pt[i], NULL, inner_encrypt, &cipherObjectVec[i]);
    }

    for (auto i = 0; i < parallel; i++)
    {
        pthread_join(pt[i], NULL);
    }
    for (int i = 0; i< cipherObjectVec.size(); i++)
    {
        for (int j = 0; j<cipherObjectVec[i].result.size(); j++)
        {
            py::array_t<uint8_t> a_arr = export_fixed_size_array(cipherObjectVec[i].result[j].get_mpz_t(), cipher_size);
            result.push_back(a_arr);
        }
    }
    return result;
}

py::list inner_batch_decrypt(pcs_public_key *pk, pcs_private_key *vk, py::list cipher_list_of_arr, int parallel)
{
    py::list result;
    long long per_parallel = cipher_list_of_arr.size()/parallel;
    mpz_t a;
    mpz_inits(a, NULL);
    std::vector<plainObject> plainObjectVec(parallel);
    for(long long i = 0; i < parallel-1; i++)
    {
       struct plainObject *plain_object = new plainObject;
       for (long long j=0; j<per_parallel; j++)
       {
            py::array_t<uint8_t> casted_array = py::cast<py::array>(cipher_list_of_arr[i*per_parallel+j]);
            auto requestCastedArray = casted_array.request();
            uint8_t* ptrArray = (uint8_t*) requestCastedArray.ptr;
            mpz_import(a, requestCastedArray.shape[0], -1, 1, 1, 0, ptrArray);
            plain_object->cipherText.push_back(mpz_class(a));
       }
       plain_object->pk = pk;
       plain_object->vk = vk;
       plainObjectVec[i] = *plain_object;
       delete  plain_object;
    }
    struct plainObject *plain_object = new plainObject;
    for (long long j=(parallel-1)*per_parallel; j<cipher_list_of_arr.size(); j++)
    {
        py::array_t<uint8_t> casted_array = py::cast<py::array>(cipher_list_of_arr[j]);
        auto requestCastedArray = casted_array.request();
        uint8_t* ptrArray = (uint8_t*) requestCastedArray.ptr;
        mpz_import(a, requestCastedArray.shape[0], -1, 1, 1, 0, ptrArray);
        plain_object->cipherText.push_back(mpz_class(a));
    }
    plain_object->pk = pk;
    plain_object->vk = vk;
    plainObjectVec[parallel-1] = *plain_object;
    delete plain_object;
    pthread_t pt[parallel];
    for (auto i = 0; i < parallel; i++)
    {
        pthread_create(&pt[i], NULL, inner_decrypt, &plainObjectVec[i]);
    }

    for (auto i = 0; i < parallel; i++)
    {
        pthread_join(pt[i], NULL);
    }

    for (int i = 0; i< plainObjectVec.size(); i++)
    {
        for (int j = 0; j<plainObjectVec[i].result.size(); j++)
        {
            result.append(plainObjectVec[i].result[j]);
        }
    }

    return result;

}

py::list inner_batch_mul(pcs_public_key *pk, py::list cipher_list_of_arr, py::list plain, int parallel, int cipher_size)
{

    py::list result;
    long long per_parallel = cipher_list_of_arr.size()/parallel;
    mpz_t a, b;
    mpz_inits(a, b, NULL);
    std::vector<cipherMulObj> cipherMulObjVec(parallel);

    for(long long i = 0; i < parallel-1; i++)
    {
       struct cipherMulObj *cipher_mulObj = new cipherMulObj;
       for (long long j=0; j<per_parallel; j++)
        {
            py::array_t<uint8_t> casted_array = py::cast<py::array>(cipher_list_of_arr[i*per_parallel+j]);
            auto requestCastedArray = casted_array.request();
            uint8_t* ptrArray = (uint8_t*) requestCastedArray.ptr;
            mpz_import(a, requestCastedArray.shape[0], -1, 1, 1, 0, ptrArray);
            cipher_mulObj->cipherText.push_back(mpz_class(a));
            cipher_mulObj->text.push_back(mpz_class(plain[i*per_parallel+j].attr("__str__")().cast<std::string>()));
        }
        cipher_mulObj->pk = pk;
        cipherMulObjVec[i] = *cipher_mulObj;
        delete  cipher_mulObj;
    }

    struct cipherMulObj *cipher_mulObj = new cipherMulObj;
    for (long long j=(parallel-1)*per_parallel; j<cipher_list_of_arr.size(); j++)
    {
        py::array_t<uint8_t> casted_array = py::cast<py::array>(cipher_list_of_arr[j]);
        auto requestCastedArray = casted_array.request();
        uint8_t* ptrArray = (uint8_t*) requestCastedArray.ptr;
        mpz_import(a, requestCastedArray.shape[0], -1, 1, 1, 0, ptrArray);
        cipher_mulObj->cipherText.push_back(mpz_class(a));
        cipher_mulObj->text.push_back(mpz_class(plain[j].attr("__str__")().cast<std::string>()));
    }
    cipher_mulObj->pk = pk;
    cipherMulObjVec[parallel-1] = *cipher_mulObj;
    delete cipher_mulObj;

    pthread_t pt[parallel];
    for (auto i = 0; i < parallel; i++)
    {
        pthread_create(&pt[i], NULL, inner_mul, &cipherMulObjVec[i]);
    }

    for (auto i = 0; i < parallel; i++)
    {
        pthread_join(pt[i], NULL);
    }

    for (int i = 0; i< cipherMulObjVec.size(); i++)
    {
        for (int j = 0; j<cipherMulObjVec[i].result.size(); j++)
        {
            py::array_t<uint8_t> a_arr = export_fixed_size_array(cipherMulObjVec[i].result[j].get_mpz_t(), cipher_size);
            result.append(a_arr);
        }
    }

    return result;

}