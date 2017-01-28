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

#ifndef FCYRPT_SCRYPT_H
#define FCYRPT_SCRYPT_H

#include "Common.h"

namespace FCrypt
{
    
class Scrypt 
{
public:
    Scrypt(const char *pass, size_t len, const uint8_t *salt, size_t slen);
    ~Scrypt();

    SecByteBlock GetAuthKey() const
    {
        SecByteBlock out(m_authkey, AES::MAX_KEYLENGTH);
        return out;
    }

    SecByteBlock GetKey() const
    {
        SecByteBlock out(m_key, AES::MAX_KEYLENGTH);
        return out;
    }

    SecByteBlock GetIV() const
    {
        SecByteBlock out(m_iv, AES::BLOCKSIZE);
        return out;
    }

    SecByteBlock GetSalt() const
    {
        SecByteBlock out(m_salt, SCRYPT_SALT);
        return out;
    }
private:
    uint8_t m_salt[SCRYPT_SALT];
    uint8_t m_key[AES::MAX_KEYLENGTH];
    uint8_t m_authkey[AES::MAX_KEYLENGTH];
    uint8_t m_iv[AES::BLOCKSIZE];
};

} /* FCrypt */ 

#endif /* ifndef FCRYPT_SCRYPT_H */
