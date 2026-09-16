#include "cert_gen.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/asn.h>

#include "codes.h"
#include "sig_algo.h"
//#include <wolfssl/wolfcrypt/error-crypt.h>
//#include <wolfssl/wolfcrypt/oid_sum.h>
//#include <wolfssl/wolfcrypt/random.h>

static int sig_algo_to_ctc(int sig_algo_type)
{
	int ret;

	switch (sig_algo_type) {
	case SIG_ALGO_RSA_2048:
	case SIG_ALGO_RSA_4096:;
	case SIG_ALGO_RSA_8192:;
		return CTC_SHA256wRSA;
	case SIG_ALGO_ECC_SECP224R1:
	case SIG_ALGO_ECC_SECP256R1:
	case SIG_ALGO_ECC_SECP384R1:
	case SIG_ALGO_ECC_SECP521R1:
		return CTC_SHA256wECDSA;
	case SIG_ALGO_ED25519:
		return CTC_ED25519;
	case SIG_ALGO_ED448:
		return CTC_ED448;
	case SIG_ALGO_MLDSA_44:
		return CTC_ML_DSA_44;
	case SIG_ALGO_MLDSA_65:
		return CTC_ML_DSA_65;
	case SIG_ALGO_MLDSA_87:
		return CTC_ML_DSA_87;
	case SIG_ALGO_SLHDSA_SHAKE128S:
		return CTC_SLH_DSA_SHAKE_128S;
	case SIG_ALGO_SLHDSA_SHAKE128F:
		return CTC_SLH_DSA_SHAKE_128F;
	case SIG_ALGO_SLHDSA_SHAKE192S:
		return CTC_SLH_DSA_SHAKE_192S;
	case SIG_ALGO_SLHDSA_SHAKE192F:
		return CTC_SLH_DSA_SHAKE_192F;
	case SIG_ALGO_SLHDSA_SHAKE256S:
		return CTC_SLH_DSA_SHAKE_256S;
	case SIG_ALGO_SLHDSA_SHAKE256F:
		return CTC_SLH_DSA_SHAKE_256F;
	case SIG_ALGO_SLHDSA_SHA2_128S:
		return CTC_SLH_DSA_SHA2_128S;
	case SIG_ALGO_SLHDSA_SHA2_128F:
		return CTC_SLH_DSA_SHA2_128F;
	case SIG_ALGO_SLHDSA_SHA2_192S:
		return CTC_SLH_DSA_SHA2_192S;
	case SIG_ALGO_SLHDSA_SHA2_192F:
		return CTC_SLH_DSA_SHA2_192F;
	case SIG_ALGO_SLHDSA_SHA2_256S:
		return CTC_SLH_DSA_SHA2_256S;
	case SIG_ALGO_SLHDSA_SHA2_256F:
		return CTC_SLH_DSA_SHA2_256F;
	case SIG_ALGO_FALCON_512:
		return CTC_FALCON_LEVEL1;
	case SIG_ALGO_FALCON_1024:
		return CTC_FALCON_LEVEL5;
	default:
		fprintf(stderr, "Unknown SIG_ALGO. Abort\n");
		abort();
	}
}

Cert *cert_create(int cert_type, const char **dns_entries, int dns_entries_sz,
		  const unsigned char (*ip_entries)[4], int ip_entries_sz,
		  const char *unit_name, const char *cn_name, int is_ca,
		  int pathlen)
{
	int ret;
	Cert *cert;
	DNS_entry *alt_entres;

	if ((cert = malloc(sizeof(*cert))) == NULL) {
		fprintf(stderr, "malloc failed\n");
		ret = CODE_ERROR;
		return NULL;
	}

	if ((ret = wc_InitCert(cert)) != WC_SUCCESS) {
		fprintf(stderr, "failed to init cert\n");
		ret = CODE_ERROR;
		goto err;
	}

	alt_entres = NULL;
	for (int i = 0; i < dns_entries_sz; i++) {
		int str_sz = strlen(*(dns_entries + i));
		if (wc_SetDNSEntry(NULL, *(dns_entries + i), str_sz,
				   ASN_DNS_TYPE, &alt_entres) != WC_SUCCESS) {
			ret = CODE_ERROR;
			goto err2;
		}
	}
	for (int i = 0; i < ip_entries_sz; i++) {
		if (wc_SetDNSEntry(NULL, (const char *)*(ip_entries + i), 4,
				   ASN_IP_TYPE, &alt_entres) != WC_SUCCESS) {
			ret = CODE_ERROR;
			goto err2;
		}
	}

	if (alt_entres != NULL &&
	    (ret = wc_SetAltNamesFromList(cert, alt_entres)) != WC_SUCCESS) {
		fprintf(stderr,
			"failed to set alternative names. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		ret = CODE_ERROR;
		goto err2;
	}

	cert->isCA = is_ca;
	cert->sigType = sig_algo_to_ctc(cert_type);
	if (pathlen != -1) {
		cert->pathLenSet = 1;
		cert->pathLen = pathlen;
		cert->basicConstCrit = 1;
	}

	if (cert->isCA)
		cert->basicConstCrit = 1;

	strncpy(cert->subject.country, "PL", CTC_NAME_SIZE);
	strncpy(cert->subject.locality, "Warsaw", CTC_NAME_SIZE);
	strncpy(cert->subject.org, "Home Lab", CTC_NAME_SIZE);
	strncpy(cert->subject.unit, unit_name, CTC_NAME_SIZE);
	strncpy(cert->subject.commonName, cn_name, CTC_NAME_SIZE);

	if (cert->isCA &&
	    (ret = wc_SetKeyUsage(cert, "keyCertSign")) != WC_SUCCESS) {
		fprintf(stderr, "failed to set key usage ext\n");
		ret = CODE_ERROR;
		goto err2;
	}

	ret = CODE_OK;
err2:
	if (alt_entres != NULL)
		FreeAltNames(alt_entres, NULL);
err:

	if (ret != CODE_OK) {
		free(cert);
		return NULL;
	} else
		return cert;
}

void cert_free(Cert *cert)
{
	free(cert);
}

int cert_gen(Cert *cert, unsigned char *der, int *der_sz,
	     unsigned char *issuer_der, int issuer_sz, struct KeyUni sub_key,
	     struct KeyUni root_key)
{
	int ret;
	int der_buf_sz = *der_sz;

	if (issuer_der != NULL &&
	    (ret = wc_SetIssuerBuffer(cert, issuer_der, issuer_sz)) !=
		    WC_SUCCESS) {
		fprintf(stderr, "failed to set certficate issuer\n");
		ret = CODE_ERROR;
		goto err;
	}

	if ((ret = wc_SetSubjectKeyIdFromPublicKey_ex(
		     cert, get_wc_key_type(sub_key.type), sub_key.key)) !=
	    WC_SUCCESS) {
		fprintf(stderr,
			"failed to set subject key id."
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		ret = CODE_ERROR;
		goto err;
	}

	if ((ret = wc_SetAuthKeyIdFromPublicKey_ex(
		     cert, get_wc_key_type(root_key.type), root_key.key)) !=
	    WC_SUCCESS) {
		fprintf(stderr,
			"failed to set auth key id."
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		ret = CODE_ERROR;
		goto err;
	}

	if ((*der_sz = wc_MakeCert_ex(cert, der, *der_sz,
				      get_wc_key_type(sub_key.type),
				      sub_key.key, g_rng)) < 0) {
		ret = *der_sz;
		fprintf(stderr,
			"failed to make certificate. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		ret = CODE_ERROR;
		goto err;
	}

	if ((*der_sz = wc_SignCert_ex(
		     cert->bodySz, sig_algo_to_ctc(root_key.type), der,
		     der_buf_sz, get_wc_key_type(root_key.type), root_key.key,
		     g_rng)) < 0) {
		ret = *der_sz;
		fprintf(stderr,
			"failed to sign certificate. "
			"err = %d, %s\n",
			ret, wc_GetErrorString(ret));
		ret = CODE_ERROR;
		goto err;
	}

	ret = CODE_OK;
err:
	return ret;
}
