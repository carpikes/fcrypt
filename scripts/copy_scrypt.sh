#!/bin/bash

mkdir lib/
cd scrypt
autoreconf -i
./configure CFLAGS='-fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 -O2'
make -j4
cd ..

A=(lib/crypto/libscrypt_sse2_a-crypto_scrypt_smix_sse2.o \
   lib/crypto/crypto_scrypt.o \ 
   lib/crypto/crypto_scrypt_smix.o \
   libcperciva/alg/sha256.o \
   libcperciva/cpusupport/cpusupport_x86_sse2.o \
   libcperciva/util/insecure_memzero.o \
   libcperciva/util/warnp.o \
)

for i in ${A[@]}; do
    I=scrypt/$i
    echo "Copying $I to lib/$i..."
    cp $I lib/
done;
