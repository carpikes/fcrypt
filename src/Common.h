/* This software is released under MIT license.
 * Copyright (c) 2017 Alain Carlucci
 * 
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef FCRYPT_COMMON_H
#define FCRYPT_COMMON_H

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <iostream>
#include <vector>
#include <algorithm>

#include <cryptopp/aes.h>
#include <cryptopp/randpool.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/hmac.h>
#include <cryptopp/modes.h>
#include "Config.h"

using namespace CryptoPP;
using std::vector;

#define SCRYPT_LEN  80 // 80 == 32(aeskey)+16(aesiv)+32(mackey)
#define SCRYPT_SALT 32 

extern "C"
{
#include <crypto_scrypt.h>
}

#pragma pack(1)
struct Data {
    uint64_t offset; // from beginning (0 == overwrite header :( )
    uint64_t size;
};

struct Hdr 
{
    uint8_t AESKey[AES::MAX_KEYLENGTH];         // 32
    uint8_t AESIV[AES::BLOCKSIZE];              // 16
    uint8_t data[AES::BLOCKSIZE];               // 16 Struct data
    uint8_t MACHdr[HMAC<SHA512>::DIGESTSIZE];   // 64
    uint8_t MACFile[HMAC<SHA512>::DIGESTSIZE];  // 64
};

struct FileHdr
{
    uint8_t salt[SCRYPT_SALT];
    Hdr headers[NUM_HEADERS]; 
};
#pragma pack()

static inline void EF_ZeroMem(void *mem, size_t size)
{
    memset(mem, 0, size);

#if defined(__x86_64__) || defined(_M_AMD64) || defined(__i386__) || defined(_X86_)
    asm volatile ("clflush (%0)" :: "r"(mem));
    asm volatile("mfence":::"memory");
#else
    #error Cannot force cache flush in this architecture. If you want to proceed, remove this line.
#endif
}

#endif /* ifndef FCRYPT_COMMON_H */
