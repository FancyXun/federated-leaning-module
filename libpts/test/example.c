#include <gmp.h>    // gmp is included implicitly
#include <libhcs.h> // master header includes everything
#include <time.h>

int main(void)
{
    // initialize data structures
    pcs_public_key *pk = pcs_init_public_key();
    pcs_private_key *vk = pcs_init_private_key();
    hcs_random *hr = hcs_init_random();

    // Generate a key pair with modulus of size 2048 bits
    pcs_generate_key_pair(pk, vk, hr, 2048);

    // libhcs works directly with gmp mpz_t types, so initialize some
    mpz_t a, a1, b, c;
    mpz_inits(a, a1, b, c, NULL);

    mpz_set_ui(a, 50);
    mpz_set_ui(a1, 50);
    mpz_set_str(b, "-76", 10);

    pcs_encrypt(pk, hr, a, a);  // Encrypt a  and store back into a
    pcs_encrypt(pk, hr, b, b);  // Encrypt b and store back into b
    gmp_printf("a = %Zd\nb = %Zd\n", a, b); // can use all gmp functions still
    char *char_arr = mpz_get_str(NULL, 10, a)
    time_t t;
    time(&t);
    printf("begin time: %s", ctime(&t));
    for(int i =0; i<1; i++){
    	pcs_ee_add(pk, c, a, b);    // Add encrypted a and b values together into c
    	pcs_decrypt(vk, c, c);      // Decrypt c back into c using private key
        gmp_printf("%Zd\n", c);     //
        pcs_ep_mul(pk, c, b, a1);
        pcs_decrypt(vk, c, c);
        gmp_printf("%Zd\n", c);
    }

    time(&t);
    printf("end time: %s", ctime(&t));

    // Cleanup all data
    mpz_clears(a, b, c, NULL);
    pcs_free_public_key(pk);
    pcs_free_private_key(vk);
    hcs_free_random(hr);

    return 0;
}