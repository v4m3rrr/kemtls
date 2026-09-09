#ifndef CERT_GEN_H
#define CERT_GEN_H

typedef struct Cert Cert;

union KeyUni;

Cert *cert_create(int key_type, const char **dns_entries, int dns_entries_sz,
		  const unsigned char (*ip_entries)[4], int ip_entries_sz,
		  const char *unit_name, const char *cn_name, int is_ca,
		  int pathlen);
void cert_free(Cert *cert);
int cert_gen(Cert *cert, int key_type, unsigned char *der, int *der_sz,
	     unsigned char *issuer_der, int issuer_sz, union KeyUni *sub_key,
	     union KeyUni *root_key);

#endif //CERT_GEN_H
