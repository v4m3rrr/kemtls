#include "gen_key.h"

#include <stdio.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>
#include <wolfssl/wolfcrypt/wc_slhdsa.h>
#include <wolfssl/wolfcrypt/falcon.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/ed448.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/asn.h>

#include "codes.h"
#include "sig_algo.h"

union key_impl {
	RsaKey rsa;
	ecc_key ecc;
	ed25519_key ed25519;
	ed448_key ed448;
	wc_MlDsaKey mldsa;
	SlhDsaKey slhdsa;
	falcon_key falcon;
	MlKemKey mlkem;
} key;

static int gen_mlkem_key(MlKemKey *gen_key, int level)
{
	int ret;

	if ((ret = wc_MlKemKey_Init(gen_key, level, NULL, 0)) != WC_SUCCESS) {
		fprintf(stderr,
			"failed to initialise MlKemKey struct. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		return CODE_ERROR;
	}

	if ((ret = wc_MlKemKey_MakeKey(gen_key, g_rng)) != WC_SUCCESS) {
		fprintf(stderr,
			"failed to make ML-KEM key. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		ret = CODE_ERROR;
		goto err_free_falcon;
	}

	ret = CODE_OK;
	return ret;

err_free_falcon:
	wc_MlKemKey_Free(gen_key);
	return ret;
}

static int gen_mlkem_key_der(unsigned char *der, int *der_sz, int level)
{
	fprintf(stderr, "%s. Not yet implemented.\n", __func__);
	abort();
}

static int gen_falcon_key(falcon_key *gen_key, int level)
{
	int ret;

	if ((ret = wc_falcon_init(gen_key)) != WC_SUCCESS) {
		fprintf(stderr,
			"failed to initialise falcon_key struct. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		return CODE_ERROR;
	}
	if ((ret = wc_falcon_set_level(gen_key, level)) != WC_SUCCESS) {
		fprintf(stderr,
			"failed to set falcon_key level. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		ret = CODE_ERROR;
		goto err_free_falcon;
	}

	if ((ret = wc_falcon_make_key(gen_key, g_rng)) != WC_SUCCESS) {
		fprintf(stderr,
			"failed to make falcon key. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		ret = CODE_ERROR;
		goto err_free_falcon;
	}

	ret = CODE_OK;
	return ret;

err_free_falcon:
	wc_falcon_free(gen_key);
	return ret;
}

static int gen_falcon_key_der(unsigned char *der, int *der_sz, int level)
{
	int ret;
	falcon_key gen_key;

	if ((ret = gen_falcon_key(&gen_key, level)) != CODE_OK) {
		fprintf(stderr, "failed to generate falcon key. ");
		ret = CODE_ERROR;
		return ret;
	}

	if ((ret = wc_Falcon_KeyToDer(&gen_key, der, *der_sz)) < 0) {
		fprintf(stderr,
			"failed to convert falcon key to der. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		ret = CODE_ERROR;
		goto err;
	}
	*der_sz = ret;

	ret = CODE_OK;
err:
	wc_falcon_free(&gen_key);

	return ret;
}

static int gen_slhdsa_key(SlhDsaKey *gen_key, int level)
{
	int ret;

#define GK_SLHDSA_SOFTWARE
#ifdef GK_SLHDSA_SOFTWARE
#pragma message "Software crypto only. Specify devId for hardware acceleration."
	if ((ret = wc_SlhDsaKey_Init(gen_key, level, NULL, INVALID_DEVID)) !=
	    WC_SUCCESS) {
		fprintf(stderr,
			"failed to initialise SlhDsaKey struct. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		return CODE_ERROR;
	}
#else
#error "Hardware acceleration is not supported."
#endif

	if ((ret = wc_SlhDsaKey_MakeKey(gen_key, g_rng)) != WC_SUCCESS) {
		fprintf(stderr,
			"failed to make slhdsa key. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		ret = CODE_ERROR;
		goto err_free_slhdsa;
	}

	ret = CODE_OK;
	return ret;

err_free_slhdsa:
	wc_SlhDsaKey_Free(gen_key);
	return ret;
}

static int gen_slhdsa_key_der(unsigned char *der, int *der_sz, int level)
{
	int ret;
	SlhDsaKey gen_key;

	if ((ret = gen_slhdsa_key(&gen_key, level)) != CODE_OK) {
		fprintf(stderr, "failed to generate slhdsa key. ");
		ret = CODE_ERROR;
		return ret;
	}

	if ((ret = wc_SlhDsaKey_KeyToDer(&gen_key, der, *der_sz)) < 0) {
		fprintf(stderr,
			"failed to convert slhdsa key to der. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		ret = CODE_ERROR;
		goto err;
	}
	*der_sz = ret;

	ret = CODE_OK;
err:
	wc_SlhDsaKey_Free(&gen_key);

	return ret;
}

static int gen_mldsa_key(wc_MlDsaKey *gen_key, int level)
{
	int ret;

#define GK_MLDSA_SOFTWARE
#ifdef GK_MLDSA_SOFTWARE
#pragma message "Software crypto only. Specify devId for hardware acceleration."
	if ((ret = wc_MlDsaKey_Init(gen_key, NULL, INVALID_DEVID)) !=
	    WC_SUCCESS) {
		fprintf(stderr,
			"failed to initialise wc_MlDsaKey struct. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		return CODE_ERROR;
	}
#else
#error "Hardware acceleration is not supported."
#endif

	if ((ret = wc_MlDsaKey_SetParams(gen_key, level)) != WC_SUCCESS) {
		fprintf(stderr,
			"failed to set params for wc_MlDsaKey struct. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		return CODE_ERROR;
	}

	if ((ret = wc_MlDsaKey_MakeKey(gen_key, g_rng)) != WC_SUCCESS) {
		fprintf(stderr,
			"failed to make mldsa key. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		ret = CODE_ERROR;
		goto err_free_mldsa;
	}

	ret = CODE_OK;
	return ret;

err_free_mldsa:
	wc_MlDsaKey_Free(gen_key);
	return ret;
}

static int gen_mldsa_key_der(unsigned char *der, int *der_sz, int level)
{
	int ret;
	wc_MlDsaKey gen_key;

	if ((ret = gen_mldsa_key(&gen_key, level)) != CODE_OK) {
		fprintf(stderr, "failed to generate mldsa key. ");
		ret = CODE_ERROR;
		return ret;
	}

	if ((ret = wc_MlDsaKey_KeyToDer(&gen_key, der, *der_sz)) < 0) {
		fprintf(stderr,
			"failed to convert mldsa key to der. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		ret = CODE_ERROR;
		goto err;
	}
	*der_sz = ret;

	ret = CODE_OK;
err:
	wc_MlDsaKey_Free(&gen_key);

	return ret;
}

static int gen_ed25519_key(ed25519_key *gen_key)
{
	int ret;

	if ((ret = wc_ed25519_init(gen_key)) != WC_SUCCESS) {
		fprintf(stderr,
			"failed to initialise ed25519_key struct. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		return CODE_ERROR;
	}

	if ((ret = wc_ed25519_make_key(g_rng, ED25519_KEY_SIZE, gen_key)) !=
	    WC_SUCCESS) {
		fprintf(stderr,
			"failed to make ed25519 key. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		ret = CODE_ERROR;
		goto err_free_ed25519;
	}

	ret = CODE_OK;
	return ret;

err_free_ed25519:
	wc_ed25519_free(gen_key);
	return ret;
}

static int gen_ed25519_key_der(unsigned char *der, int *der_sz)
{
	int ret;
	ed25519_key gen_key;

	if ((ret = gen_ed25519_key(&gen_key)) != CODE_OK) {
		fprintf(stderr, "failed to generate ed25519 key. ");
		ret = CODE_ERROR;
		return ret;
	}

	if ((ret = wc_Ed25519KeyToDer(&gen_key, der, *der_sz)) < 0) {
		fprintf(stderr,
			"failed to convert ed25519 key to der. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		ret = CODE_ERROR;
		goto err;
	}
	*der_sz = ret;

	ret = CODE_OK;
err:
	wc_ed25519_free(&gen_key);

	return ret;
}

static int gen_ed448_key(ed448_key *gen_key)
{
	int ret;

	if ((ret = wc_ed448_init(gen_key)) != WC_SUCCESS) {
		fprintf(stderr,
			"failed to initialise ed448_key struct. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		return CODE_ERROR;
	}

	if ((ret = wc_ed448_make_key(g_rng, ED448_KEY_SIZE, gen_key)) !=
	    WC_SUCCESS) {
		fprintf(stderr,
			"failed to make ed448 key. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		ret = CODE_ERROR;
		goto err_free_ed448;
	}

	ret = CODE_OK;
	return ret;

err_free_ed448:
	wc_ed448_free(gen_key);
	return ret;
}

static int gen_ed448_key_der(unsigned char *der, int *der_sz)
{
	int ret;
	ed448_key gen_key;

	if ((ret = gen_ed448_key(&gen_key)) != CODE_OK) {
		fprintf(stderr, "failed to generate ed448 key. ");
		ret = CODE_ERROR;
		return ret;
	}

	if ((ret = wc_Ed448KeyToDer(&gen_key, der, *der_sz)) < 0) {
		fprintf(stderr,
			"failed to convert ed448 key to der. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		ret = CODE_ERROR;
		goto err;
	}
	*der_sz = ret;

	ret = CODE_OK;
err:
	wc_ed448_free(&gen_key);

	return ret;
}

static int gen_ecc_key(ecc_key *gen_key, int curve_id)
{
	int keysize;
	int ret;

	if ((ret = wc_ecc_init(gen_key)) != WC_SUCCESS) {
		fprintf(stderr,
			"failed to initialise ecc_key struct. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		return CODE_ERROR;
	}

	if ((keysize = wc_ecc_get_curve_size_from_id(curve_id)) < 0) {
		fprintf(stderr,
			"failed to get curve size. "
			"curve_id = %d"
			"err = %d, %s\n",
			curve_id, ret, wc_GetErrorString(ret));
		ret = CODE_ERROR;
		goto err_free_ecc;
	}

	if ((ret = wc_ecc_make_key_ex(g_rng, keysize, gen_key, curve_id)) !=
	    WC_SUCCESS) {
		fprintf(stderr,
			"failed to make ecc key. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		ret = CODE_ERROR;
		goto err_free_ecc;
	}

	ret = CODE_OK;
	return ret;

err_free_ecc:
	wc_ecc_free(gen_key);
	return ret;
}

static int gen_ecc_key_der(unsigned char *der, int *der_sz, int curve_id)
{
	int ret;
	ecc_key gen_key;

	if ((ret = gen_ecc_key(&gen_key, curve_id)) != CODE_OK) {
		fprintf(stderr, "failed to generate ecc key. ");
		ret = CODE_ERROR;
		return ret;
	}

	if ((ret = wc_EccKeyToDer(&gen_key, der, *der_sz)) < 0) {
		fprintf(stderr,
			"failed to convert ecc key to der. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		ret = CODE_ERROR;
		goto err;
	}
	*der_sz = ret;

	ret = CODE_OK;
err:
	wc_ecc_free(&gen_key);

	return ret;
}

static int gen_rsa_key(RsaKey *gen_key, int keysize)
{
	int ret;

	if (keysize < RSA_MIN_SIZE || keysize > RSA_MAX_SIZE) {
		fprintf(stderr,
			"wrong keysize. "
			"keysize must be in (%d,%d)\n",
			RSA_MIN_SIZE, RSA_MAX_SIZE);
		return CODE_ERROR;
	}

	if ((ret = wc_InitRsaKey(gen_key, NULL)) != WC_SUCCESS) {
		fprintf(stderr,
			"failed to initialise rsa struct. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		return CODE_ERROR;
	}

	if ((ret = wc_MakeRsaKey(gen_key, keysize, WC_RSA_EXPONENT, g_rng)) !=
	    WC_SUCCESS) {
		fprintf(stderr,
			"failed to make rsa key. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		ret = CODE_ERROR;
		goto err_free_rsa;
	}

	ret = CODE_OK;
	return ret;

err_free_rsa:
	if (wc_FreeRsaKey(gen_key) != WC_SUCCESS) {
		fprintf(stderr, "Critical faliure wc_FreeRsaKey\n");
		ret = CODE_ERROR;
	}
	return ret;
}

static int gen_rsa_key_der(unsigned char *der, int *der_sz, int keysize)
{
	int ret;
	RsaKey gen_key;

	if ((ret = gen_rsa_key(&gen_key, keysize)) != CODE_OK) {
		fprintf(stderr, "failed to generate rsa key. ");
		ret = CODE_ERROR;
		return ret;
	}

	if ((ret = wc_RsaKeyToDer(&gen_key, der, *der_sz)) < 0) {
		fprintf(stderr,
			"failed to convert rsa key to der. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		ret = CODE_ERROR;
		goto err;
	}
	*der_sz = ret;

	ret = CODE_OK;

err:
	wc_FreeRsaKey(&gen_key);
	return ret;
}

int gen_key(struct KeyUni key)
{
	int ret;

	switch (key.type) {
	case SIG_ALGO_RSA_2048:
		ret = gen_rsa_key(&key.key->rsa, 2048);
		break;
	case SIG_ALGO_RSA_4096:;
		ret = gen_rsa_key(&key.key->rsa, 4096);
		break;
	case SIG_ALGO_RSA_8192:;
		ret = gen_rsa_key(&key.key->rsa, 8192);
		break;
	case SIG_ALGO_ECC_SECP224R1:
		ret = gen_ecc_key(&key.key->ecc, ECC_SECP224R1);
		break;
	case SIG_ALGO_ECC_SECP256R1:
		ret = gen_ecc_key(&key.key->ecc, ECC_SECP256R1);
		break;
	case SIG_ALGO_ECC_SECP384R1:
		ret = gen_ecc_key(&key.key->ecc, ECC_SECP384R1);
		break;
	case SIG_ALGO_ECC_SECP521R1:
		ret = gen_ecc_key(&key.key->ecc, ECC_SECP521R1);
		break;
	case SIG_ALGO_ED25519:
		ret = gen_ed25519_key(&key.key->ed25519);
		break;
	case SIG_ALGO_ED448:
		ret = gen_ed448_key(&key.key->ed448);
		break;
	case SIG_ALGO_MLDSA_44:
		ret = gen_mldsa_key(&key.key->mldsa, WC_ML_DSA_44);
		break;
	case SIG_ALGO_MLDSA_65:
		ret = gen_mldsa_key(&key.key->mldsa, WC_ML_DSA_65);
		break;
	case SIG_ALGO_MLDSA_87:
		ret = gen_mldsa_key(&key.key->mldsa, WC_ML_DSA_87);
		break;
	case SIG_ALGO_SLHDSA_SHAKE128S:
		ret = gen_slhdsa_key(&key.key->slhdsa, SLHDSA_SHAKE128S);
		break;
	case SIG_ALGO_SLHDSA_SHAKE128F:
		ret = gen_slhdsa_key(&key.key->slhdsa, SLHDSA_SHAKE128F);
		break;
	case SIG_ALGO_SLHDSA_SHAKE192S:
		ret = gen_slhdsa_key(&key.key->slhdsa, SLHDSA_SHAKE192S);
		break;
	case SIG_ALGO_SLHDSA_SHAKE192F:
		ret = gen_slhdsa_key(&key.key->slhdsa, SLHDSA_SHAKE192F);
		break;
	case SIG_ALGO_SLHDSA_SHAKE256S:
		ret = gen_slhdsa_key(&key.key->slhdsa, SLHDSA_SHAKE256S);
		break;
	case SIG_ALGO_SLHDSA_SHAKE256F:
		ret = gen_slhdsa_key(&key.key->slhdsa, SLHDSA_SHAKE256F);
		break;
	case SIG_ALGO_SLHDSA_SHA2_128S:
		ret = gen_slhdsa_key(&key.key->slhdsa, SLHDSA_SHA2_128S);
		break;
	case SIG_ALGO_SLHDSA_SHA2_128F:
		ret = gen_slhdsa_key(&key.key->slhdsa, SLHDSA_SHA2_128F);
		break;
	case SIG_ALGO_SLHDSA_SHA2_192S:
		ret = gen_slhdsa_key(&key.key->slhdsa, SLHDSA_SHA2_192S);
		break;
	case SIG_ALGO_SLHDSA_SHA2_192F:
		ret = gen_slhdsa_key(&key.key->slhdsa, SLHDSA_SHA2_192F);
		break;
	case SIG_ALGO_SLHDSA_SHA2_256S:
		ret = gen_slhdsa_key(&key.key->slhdsa, SLHDSA_SHA2_256S);
		break;
	case SIG_ALGO_SLHDSA_SHA2_256F:
		ret = gen_slhdsa_key(&key.key->slhdsa, SLHDSA_SHA2_256F);
		break;
	case SIG_ALGO_FALCON_512:
		ret = gen_falcon_key(&key.key->falcon, FALCON_LEVEL1);
		break;
	case SIG_ALGO_FALCON_1024:
		ret = gen_falcon_key(&key.key->falcon, FALCON_LEVEL5);
		break;
	case SIG_ALGO_MLKEM_512:
		ret = gen_mlkem_key(&key.key->mlkem, WC_ML_KEM_512);
		break;
	case SIG_ALGO_MLKEM_768:
		ret = gen_mlkem_key(&key.key->mlkem, WC_ML_KEM_768);
		break;
	case SIG_ALGO_MLKEM_1024:
		ret = gen_mlkem_key(&key.key->mlkem, WC_ML_KEM_1024);
		break;
	default:
		fprintf(stderr, "Unknown SIG_ALGO. Abort\n");
		abort();
	}

	return ret;
}

int gen_key_der(int sig_algo_type, unsigned char *der, int *der_sz)
{
	int ret;

	switch (sig_algo_type) {
	case SIG_ALGO_RSA_2048:
		ret = gen_rsa_key_der(der, der_sz, 2048);
		break;
	case SIG_ALGO_RSA_4096:;
		ret = gen_rsa_key_der(der, der_sz, 4096);
		break;
	case SIG_ALGO_RSA_8192:;
		ret = gen_rsa_key_der(der, der_sz, 8192);
		break;
	case SIG_ALGO_ECC_SECP224R1:
		ret = gen_ecc_key_der(der, der_sz, ECC_SECP224R1);
		break;
	case SIG_ALGO_ECC_SECP256R1:
		ret = gen_ecc_key_der(der, der_sz, ECC_SECP256R1);
		break;
	case SIG_ALGO_ECC_SECP384R1:
		ret = gen_ecc_key_der(der, der_sz, ECC_SECP384R1);
		break;
	case SIG_ALGO_ECC_SECP521R1:
		ret = gen_ecc_key_der(der, der_sz, ECC_SECP521R1);
		break;
	case SIG_ALGO_ED25519:
		ret = gen_ed25519_key_der(der, der_sz);
		break;
	case SIG_ALGO_ED448:
		ret = gen_ed448_key_der(der, der_sz);
		break;
	case SIG_ALGO_MLDSA_44:
		ret = gen_mldsa_key_der(der, der_sz, WC_ML_DSA_44);
		break;
	case SIG_ALGO_MLDSA_65:
		ret = gen_mldsa_key_der(der, der_sz, WC_ML_DSA_65);
		break;
	case SIG_ALGO_MLDSA_87:
		ret = gen_mldsa_key_der(der, der_sz, WC_ML_DSA_87);
		break;
	case SIG_ALGO_SLHDSA_SHAKE128S:
		ret = gen_slhdsa_key_der(der, der_sz, SLHDSA_SHAKE128S);
		break;
	case SIG_ALGO_SLHDSA_SHAKE128F:
		ret = gen_slhdsa_key_der(der, der_sz, SLHDSA_SHAKE128F);
		break;
	case SIG_ALGO_SLHDSA_SHAKE192S:
		ret = gen_slhdsa_key_der(der, der_sz, SLHDSA_SHAKE192S);
		break;
	case SIG_ALGO_SLHDSA_SHAKE192F:
		ret = gen_slhdsa_key_der(der, der_sz, SLHDSA_SHAKE192F);
		break;
	case SIG_ALGO_SLHDSA_SHAKE256S:
		ret = gen_slhdsa_key_der(der, der_sz, SLHDSA_SHAKE256S);
		break;
	case SIG_ALGO_SLHDSA_SHAKE256F:
		ret = gen_slhdsa_key_der(der, der_sz, SLHDSA_SHAKE256F);
		break;
	case SIG_ALGO_SLHDSA_SHA2_128S:
		ret = gen_slhdsa_key_der(der, der_sz, SLHDSA_SHA2_128S);
		break;
	case SIG_ALGO_SLHDSA_SHA2_128F:
		ret = gen_slhdsa_key_der(der, der_sz, SLHDSA_SHA2_128F);
		break;
	case SIG_ALGO_SLHDSA_SHA2_192S:
		ret = gen_slhdsa_key_der(der, der_sz, SLHDSA_SHA2_192S);
		break;
	case SIG_ALGO_SLHDSA_SHA2_192F:
		ret = gen_slhdsa_key_der(der, der_sz, SLHDSA_SHA2_192F);
		break;
	case SIG_ALGO_SLHDSA_SHA2_256S:
		ret = gen_slhdsa_key_der(der, der_sz, SLHDSA_SHA2_256S);
		break;
	case SIG_ALGO_SLHDSA_SHA2_256F:
		ret = gen_slhdsa_key_der(der, der_sz, SLHDSA_SHA2_256F);
		break;
	case SIG_ALGO_FALCON_512:
		ret = gen_falcon_key_der(der, der_sz, FALCON_LEVEL1);
		break;
	case SIG_ALGO_FALCON_1024:
		ret = gen_falcon_key_der(der, der_sz, FALCON_LEVEL5);
		break;
	default:
		fprintf(stderr, "Unknown SIG_ALGO. Abort\n");
		abort();
	}

	return ret;
}

struct KeyUni gen_key_create(int sig_algo_type)
{
	struct KeyUni key;
	key.type = sig_algo_type;
	key.key = malloc(sizeof(*key.key));
	return key;
}

int key_to_der(struct KeyUni key, unsigned char *der, int *der_sz)
{
	switch (key.type) {
	case SIG_ALGO_RSA:
	case SIG_ALGO_RSA_2048:
	case SIG_ALGO_RSA_4096:
	case SIG_ALGO_RSA_8192:
		*der_sz = wc_RsaKeyToDer(&key.key->rsa, der, *der_sz);
		break;
	case SIG_ALGO_ECC:
	case SIG_ALGO_ECC_SECP224R1:
	case SIG_ALGO_ECC_SECP256R1:
	case SIG_ALGO_ECC_SECP384R1:
	case SIG_ALGO_ECC_SECP521R1:
		*der_sz = wc_EccKeyToDer(&key.key->ecc, der, *der_sz);
		break;
	case SIG_ALGO_ED25519:
		*der_sz = wc_Ed25519PrivateKeyToDer(&key.key->ed25519, der,
						    *der_sz);
		break;
	case SIG_ALGO_ED448:
		*der_sz =
			wc_Ed448PrivateKeyToDer(&key.key->ed448, der, *der_sz);
		break;
	case SIG_ALGO_MLDSA:
	case SIG_ALGO_MLDSA_44:
	case SIG_ALGO_MLDSA_65:
	case SIG_ALGO_MLDSA_87:
		*der_sz = wc_MlDsaKey_PrivateKeyToDer(&key.key->mldsa, der,
						      *der_sz);
		break;
	case SIG_ALGO_SLHDSA:
	case SIG_ALGO_SLHDSA_SHAKE128S:
	case SIG_ALGO_SLHDSA_SHAKE128F:
	case SIG_ALGO_SLHDSA_SHAKE192S:
	case SIG_ALGO_SLHDSA_SHAKE192F:
	case SIG_ALGO_SLHDSA_SHAKE256S:
	case SIG_ALGO_SLHDSA_SHAKE256F:
	case SIG_ALGO_SLHDSA_SHA2_128S:
	case SIG_ALGO_SLHDSA_SHA2_128F:
	case SIG_ALGO_SLHDSA_SHA2_192S:
	case SIG_ALGO_SLHDSA_SHA2_192F:
	case SIG_ALGO_SLHDSA_SHA2_256S:
	case SIG_ALGO_SLHDSA_SHA2_256F:
		*der_sz = wc_SlhDsaKey_PrivateKeyToDer(&key.key->slhdsa, der,
						       *der_sz);
		break;
	case SIG_ALGO_FALCON:
	case SIG_ALGO_FALCON_512:
	case SIG_ALGO_FALCON_1024:
		*der_sz = wc_Falcon_PrivateKeyToDer(&key.key->falcon, der,
						    *der_sz);
		break;
	case SIG_ALGO_MLKEM:
	case SIG_ALGO_MLKEM_512:
	case SIG_ALGO_MLKEM_768:
	case SIG_ALGO_MLKEM_1024:
		*der_sz = wc_MlKemKey_PrivateKeyToDer(&key.key->mlkem, der,
						      *der_sz);
		break;
	default:
		fprintf(stderr, "Unknown SIG_ALGO. Abort\n");
		abort();
	}

	if (*der_sz < 0)
		return CODE_ERROR;

	return CODE_OK;
}

void gen_key_free(struct KeyUni key)
{
	switch (key.type) {
	case SIG_ALGO_RSA:
	case SIG_ALGO_RSA_2048:
	case SIG_ALGO_RSA_4096:
	case SIG_ALGO_RSA_8192:
		wc_FreeRsaKey(&key.key->rsa);
		break;
	case SIG_ALGO_ECC:
	case SIG_ALGO_ECC_SECP224R1:
	case SIG_ALGO_ECC_SECP256R1:
	case SIG_ALGO_ECC_SECP384R1:
	case SIG_ALGO_ECC_SECP521R1:
		wc_ecc_free(&key.key->ecc);
		break;
	case SIG_ALGO_ED25519:
		wc_ed25519_free(&key.key->ed25519);
		break;
	case SIG_ALGO_ED448:
		wc_ed448_free(&key.key->ed448);
		break;
	case SIG_ALGO_MLDSA:
	case SIG_ALGO_MLDSA_44:
	case SIG_ALGO_MLDSA_65:
	case SIG_ALGO_MLDSA_87:
		wc_MlDsaKey_Free(&key.key->mldsa);
		break;
	case SIG_ALGO_SLHDSA:
	case SIG_ALGO_SLHDSA_SHAKE128S:
	case SIG_ALGO_SLHDSA_SHAKE128F:
	case SIG_ALGO_SLHDSA_SHAKE192S:
	case SIG_ALGO_SLHDSA_SHAKE192F:
	case SIG_ALGO_SLHDSA_SHAKE256S:
	case SIG_ALGO_SLHDSA_SHAKE256F:
	case SIG_ALGO_SLHDSA_SHA2_128S:
	case SIG_ALGO_SLHDSA_SHA2_128F:
	case SIG_ALGO_SLHDSA_SHA2_192S:
	case SIG_ALGO_SLHDSA_SHA2_192F:
	case SIG_ALGO_SLHDSA_SHA2_256S:
	case SIG_ALGO_SLHDSA_SHA2_256F:
		wc_SlhDsaKey_Free(&key.key->slhdsa);
		break;
	case SIG_ALGO_FALCON:
	case SIG_ALGO_FALCON_512:
	case SIG_ALGO_FALCON_1024:
		wc_falcon_free(&key.key->falcon);
		break;
	case SIG_ALGO_MLKEM:
	case SIG_ALGO_MLKEM_512:
	case SIG_ALGO_MLKEM_768:
	case SIG_ALGO_MLKEM_1024:
		wc_MlKemKey_Free(&key.key->mlkem);
		break;
	default:
		fprintf(stderr, "Unknown SIG_ALGO. Abort\n");
		abort();
	}
}
