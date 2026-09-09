#!/bin/sh

list=(
        SIG_ALGO_RSA_2048
        SIG_ALGO_RSA_4096
        #SIG_ALGO_RSA_8192

        SIG_ALGO_ECC_SECP224R1
        SIG_ALGO_ECC_SECP256R1
        SIG_ALGO_ECC_SECP384R1
        SIG_ALGO_ECC_SECP521R1

        SIG_ALGO_ED25519
        SIG_ALGO_ED448

        SIG_ALGO_MLDSA_44
        SIG_ALGO_MLDSA_65
        SIG_ALGO_MLDSA_87

        SIG_ALGO_SLHDSA_SHAKE128S
        SIG_ALGO_SLHDSA_SHAKE128F
        SIG_ALGO_SLHDSA_SHAKE192S
        SIG_ALGO_SLHDSA_SHAKE192F
        SIG_ALGO_SLHDSA_SHAKE256S
        SIG_ALGO_SLHDSA_SHAKE256F

        SIG_ALGO_SLHDSA_SHA2_128S
        SIG_ALGO_SLHDSA_SHA2_128F
        SIG_ALGO_SLHDSA_SHA2_192S
        SIG_ALGO_SLHDSA_SHA2_192F
        SIG_ALGO_SLHDSA_SHA2_256S
        SIG_ALGO_SLHDSA_SHA2_256F

        SIG_ALGO_FALCON_512
        SIG_ALGO_FALCON_1024
)

mkdir -p keys

for key_type in "${list[@]}"; do
        echo "$key_type"
        ./build/debug/certs/cert "$key_type" "keys/$key_type.der"
done

