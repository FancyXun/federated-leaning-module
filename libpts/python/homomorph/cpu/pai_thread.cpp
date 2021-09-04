#include <gmp.h>
#include <libhcs.h>
#include <pybind11/pybind11.h>
#include <pybind11/eigen.h>
#include <pybind11/stl.h>
#include <libhcs.h> 

#include "pai_thread.h"
#include "../dataIO.h"

namespace py = pybind11;

namespace cpu
{
    namespace optimization
    {
        struct cipherObject
        {
            std::vector<long long> text;
            pcs_public_key *pk;
            hcs_random *hr;
            int cipher_size;
            std::vector<py::array_t<uint8_t>> result;
        };

        static void* encrypt(void *arguments)
        {
            mpz_t a;
            struct cipherObject *cipher_object = (cipherObject *)arguments;
            for(long long i = 0; i<cipher_object->text.size(); ++i)
            {
                mpz_init_set_str(a, std::to_string(cipher_object->text[i]).c_str(), 10);
                pcs_encrypt(cipher_object->pk, cipher_object->hr, a, a);

                py::array_t<uint8_t> a_arr = export_fixed_size_array(a, cipher_object->cipher_size);
                cipher_object->result.push_back(a_arr);
            }
        }

        std::vector<py::array_t<uint8_t>> batch_encrypt(pcs_public_key* pk, hcs_random *hr, int cipher_size,
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
                pthread_create(&pt[i], NULL, encrypt, &cipherObjectVec[i]);
            }

            for (auto i = 0; i < parallel; i++)
            {
                pthread_join(pt[i], NULL);
            }

            for (int i = 0; i< cipherObjectVec.size(); i++)
            {
                for (int j = 0; j<cipherObjectVec[i].result.size(); j++)
                {
                   result.push_back(cipherObjectVec[i].result[j]);
                }
            }

        }
    }
}