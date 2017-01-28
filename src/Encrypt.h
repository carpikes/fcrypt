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

#ifndef FCRYPT_ENCRYPT_H
#define FCRYPT_ENCRYPT_H

#include "Common.h"
#include "Scrypt.h"

namespace FCrypt
{

class Encrypt 
{
public:
    Encrypt(const char *path, uint64_t padMin, uint64_t padMax);
    virtual ~Encrypt();

    bool IsOk() const;

    void Discard();
    
    // return the used salt (must be in common for all files in the outfile)
    void GetSalt(uint8_t *out, size_t outlen) const;

    bool AddFile(const Scrypt& scrypt, const char *path);

private:
    FILE * m_fp;                    // Out file pointer
    const char *m_path;             // Out file name/path
    bool m_used_slots[NUM_HEADERS]; // Used slots in out file
    bool m_ok;                      // Ok: Out file is open and ready
    FileHdr m_hdr;                  // Contains the header (written at the end)
    uint64_t m_padmin, m_padmax;

    void WriteHeader();
    void WritePadding();

    Encrypt(const Encrypt&) = delete;
    Encrypt(Encrypt&&) = delete;
    Encrypt& operator=(const Encrypt&) & = delete;
    Encrypt& operator=(Encrypt&&) & = delete;
};

} /* FCrypt */

#endif /* ifndef FCRYPT_OUTFILE_H */
