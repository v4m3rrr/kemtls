#include "sig_algo.h"

#include <string.h>

#include "codes.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/oid_sum.h>

WC_RNG *g_rng;

int sig_algo_init()
{
	int ret;

	if ((ret = wolfCrypt_Init()) != WC_SUCCESS) {
		fprintf(stderr,
			"failed to initialise wolfCrypt. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		ret = CODE_ERROR;
		return ret;
	}

	g_rng = malloc(sizeof(*g_rng));

	if ((ret = wc_InitRng(g_rng)) != WC_SUCCESS) {
		fprintf(stderr,
			"failed to initialise rng. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		ret = CODE_ERROR;
		goto error;
	}

	if (ret == WC_SUCCESS)
		ret = CODE_OK;
	return ret;
error:
	if (wolfCrypt_Cleanup() != WC_SUCCESS)
		fprintf(stderr, "Critical faliure wolfCrypt_Cleanup\n");

	return CODE_ERROR;
}

int sig_algo_cleanup()
{
	int ret;

	if (wc_FreeRng(g_rng) != WC_SUCCESS) {
		fprintf(stderr, "Critical faliure wc_FreeRng\n");
		ret = CODE_ERROR;
	}

	if (wolfCrypt_Cleanup() != WC_SUCCESS) {
		fprintf(stderr, "Critical faliure wolfCrypt_Cleanup\n");
		ret = CODE_ERROR;
	}

	return ret;
}

#define get_key_type_helper(x)    \
	if (strcmp(str, #x) == 0) \
	return x

int get_key_type_from_str(const char *str)
{
	// clang-format off
	get_key_type_helper(SIG_ALGO_RSA_2048);
        else get_key_type_helper(SIG_ALGO_RSA_4096);
        else get_key_type_helper(SIG_ALGO_RSA_8192);

        else get_key_type_helper(SIG_ALGO_ECC_SECP224R1);
        else get_key_type_helper(SIG_ALGO_ECC_SECP256R1);
        else get_key_type_helper(SIG_ALGO_ECC_SECP384R1);
        else get_key_type_helper(SIG_ALGO_ECC_SECP521R1);

        else get_key_type_helper(SIG_ALGO_ED25519); 
        else get_key_type_helper(SIG_ALGO_ED448); 

        else get_key_type_helper(SIG_ALGO_MLDSA_44); 
        else get_key_type_helper(SIG_ALGO_MLDSA_65); 
        else get_key_type_helper(SIG_ALGO_MLDSA_87); 

        else get_key_type_helper(SIG_ALGO_SLHDSA_SHAKE128S); 
        else get_key_type_helper(SIG_ALGO_SLHDSA_SHAKE128F); 
        else get_key_type_helper(SIG_ALGO_SLHDSA_SHAKE192S); 
        else get_key_type_helper(SIG_ALGO_SLHDSA_SHAKE192F); 
        else get_key_type_helper(SIG_ALGO_SLHDSA_SHAKE256S); 
        else get_key_type_helper(SIG_ALGO_SLHDSA_SHAKE256F); 

        else get_key_type_helper(SIG_ALGO_SLHDSA_SHA2_128S); 
        else get_key_type_helper(SIG_ALGO_SLHDSA_SHA2_128F); 
        else get_key_type_helper(SIG_ALGO_SLHDSA_SHA2_192S); 
        else get_key_type_helper(SIG_ALGO_SLHDSA_SHA2_192F); 
        else get_key_type_helper(SIG_ALGO_SLHDSA_SHA2_256S); 
        else get_key_type_helper(SIG_ALGO_SLHDSA_SHA2_256F); 

        else get_key_type_helper(SIG_ALGO_FALCON_512); 
        else get_key_type_helper(SIG_ALGO_FALCON_1024); 

        else get_key_type_helper(SIG_ALGO_MLKEM_512); 
        else get_key_type_helper(SIG_ALGO_MLKEM_768); 
        else get_key_type_helper(SIG_ALGO_MLKEM_1024); 

        else return CODE_ERROR;
        //clang-format on
}

int get_wc_key_type(int sig_algo_type)
{
	switch (sig_algo_type) {
	case SIG_ALGO_RSA:
	case SIG_ALGO_RSA_2048:
	case SIG_ALGO_RSA_4096:
	case SIG_ALGO_RSA_8192:
		return RSA_TYPE;
	case SIG_ALGO_ECC:
	case SIG_ALGO_ECC_SECP224R1:
	case SIG_ALGO_ECC_SECP256R1:
	case SIG_ALGO_ECC_SECP384R1:
	case SIG_ALGO_ECC_SECP521R1:
		return ECC_TYPE;
	case SIG_ALGO_ED25519:
		return ED25519_TYPE;
	case SIG_ALGO_ED448:
		return ED448_TYPE;
	case SIG_ALGO_MLDSA_44:
		return ML_DSA_44_TYPE;
	case SIG_ALGO_MLDSA_65:
		return ML_DSA_65_TYPE;
	case SIG_ALGO_MLDSA_87:
		return ML_DSA_87_TYPE;
	case SIG_ALGO_SLHDSA_SHAKE128S:
		return SLH_DSA_SHAKE_128S_TYPE;
	case SIG_ALGO_SLHDSA_SHAKE128F:
		return SLH_DSA_SHAKE_128F_TYPE;
	case SIG_ALGO_SLHDSA_SHAKE192S:
		return SLH_DSA_SHAKE_192S_TYPE;
	case SIG_ALGO_SLHDSA_SHAKE192F:
		return SLH_DSA_SHAKE_192F_TYPE;
	case SIG_ALGO_SLHDSA_SHAKE256S:
		return SLH_DSA_SHAKE_256S_TYPE;
	case SIG_ALGO_SLHDSA_SHAKE256F:
		return SLH_DSA_SHAKE_256F_TYPE;
	case SIG_ALGO_SLHDSA_SHA2_128S:
		return SLH_DSA_SHA2_128S_TYPE;
	case SIG_ALGO_SLHDSA_SHA2_128F:
		return SLH_DSA_SHA2_128F_TYPE;
	case SIG_ALGO_SLHDSA_SHA2_192S:
		return SLH_DSA_SHA2_192S_TYPE;
	case SIG_ALGO_SLHDSA_SHA2_192F:
		return SLH_DSA_SHA2_192F_TYPE;
	case SIG_ALGO_SLHDSA_SHA2_256S:
		return SLH_DSA_SHA2_256S_TYPE;
	case SIG_ALGO_SLHDSA_SHA2_256F:
		return SLH_DSA_SHA2_256F_TYPE;
	case SIG_ALGO_FALCON_512:
		return FALCON_LEVEL1_TYPE;
	case SIG_ALGO_FALCON_1024:
		return FALCON_LEVEL5_TYPE;
	case SIG_ALGO_MLKEM_512:
	case SIG_ALGO_MLKEM_768:
	case SIG_ALGO_MLKEM_1024:
		return MLKEM_TYPE;
               
	default:
		fprintf(stderr, "Unknown SIG_ALGO. Abort\n");
		abort();
	}
}
