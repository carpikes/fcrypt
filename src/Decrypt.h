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

#ifndef FCRYPT_DECRYPT_H
#define FCRYPT_DECRYPT_H

#include "Common.h"
#include "Scrypt.h"

namespace FCrypt
{

class Decrypt
{
public:
    Decrypt(const char *infile, const char *outfile);
    virtual ~Decrypt();

    bool IsOk() const;
    const FileHdr& GetHeader() const;
    bool Run(const Scrypt& scrypt) const;

private:
    bool m_ok;
    FILE *m_infp, *m_outfp;
    FileHdr m_hdr;

    Decrypt(const Decrypt&) = delete;
    Decrypt(Decrypt&&) = delete;
    Decrypt& operator=(const Decrypt&) & = delete;
    Decrypt& operator=(Decrypt&&) & = delete;
};

} /* FCrypt */

#endif /* ifndef FCRYPT_DECRYPT_H */
