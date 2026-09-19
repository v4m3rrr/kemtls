#ifndef GEN_KEY_H
#define GEN_KEY_H

union key_impl;

struct KeyUni {
	int type;
	union key_impl *key;
};

int get_key_type_from_str(const char *str);
int gen_key(struct KeyUni key);
int key_to_der(struct KeyUni key, unsigned char *der, int *der_sz);
//int gen_key_der(int sig_algo_type, unsigned char *der, int *der_sz);

struct KeyUni gen_key_create(int sig_algo_type);
void gen_key_free(struct KeyUni key);

#endif // GEN_KEY_H
