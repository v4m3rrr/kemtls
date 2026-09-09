#ifndef GEN_KEY_H
#define GEN_KEY_H

union KeyUni;

int get_key_type_from_str(const char *str);
int gen_key(int sig_algo_type, union KeyUni *key);
int gen_key_der(int sig_algo_type, unsigned char *der, int *der_sz);

union KeyUni *gen_key_create(int sig_algo_type);
void gen_key_free(int sig_algo_type, union KeyUni *key);

#endif // GEN_KEY_H
