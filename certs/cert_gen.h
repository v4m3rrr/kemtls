#ifndef CERT_GEN_H
#define CERT_GEN_H

#include "gen_key.h"

typedef struct Cert Cert;

Cert *cert_create(int cert_type, const char **dns_entries, int dns_entries_sz,
		  const unsigned char (*ip_entries)[4], int ip_entries_sz,
		  const char *unit_name, const char *cn_name, int is_ca,
		  int pathlen);
void cert_free(Cert *cert);
int cert_gen(Cert *cert, unsigned char *der, int *der_sz,
	     unsigned char *issuer_der, int issuer_sz, struct KeyUni sub_key,
	     struct KeyUni root_key);

#endif //CERT_GEN_H
