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

#include "Scrypt.h"

namespace FCrypt
{

Scrypt::Scrypt(const char *pass, size_t len, const uint8_t *salt, size_t slen) 
{
    assert(SCRYPT_LEN == 80);

    memcpy(m_salt, salt, slen);

    uint8_t key[SCRYPT_LEN];

    crypto_scrypt((const uint8_t *) pass, len, m_salt, sizeof(m_salt), 
                    SCRYPT_N, SCRYPT_R, SCRYPT_P, key, sizeof(key));

    uint8_t *ptr = key;

    memcpy(m_key, ptr, AES::MAX_KEYLENGTH); ptr += AES::MAX_KEYLENGTH;
    memcpy(m_iv, ptr, AES::BLOCKSIZE); ptr += AES::BLOCKSIZE;
    memcpy(m_authkey, ptr, AES::MAX_KEYLENGTH); ptr += AES::MAX_KEYLENGTH;

    EF_ZeroMem(key, sizeof(key));
}

Scrypt::~Scrypt() 
{
    EF_ZeroMem(m_key, sizeof(m_key));
    EF_ZeroMem(m_authkey, sizeof(m_authkey));
    EF_ZeroMem(m_salt, sizeof(m_salt));
    EF_ZeroMem(m_iv, sizeof(m_iv));
}

} /* FCrypt */
