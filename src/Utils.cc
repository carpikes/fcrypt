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

#include "Utils.h"
#include "Scrypt.h"
#include "Encrypt.h"
#include "Decrypt.h"

namespace FCrypt
{

void Utils::EncryptHelper(int n_files, const char *path[], char *outfile, 
                          int64_t padMin, int64_t padMax)
{
    if(n_files <= 0 || n_files >= NUM_HEADERS)
    {
        fprintf(stderr, "Too many files. Max files per package: %d\n", NUM_HEADERS);
        return;
    }

    if(padMin <= 0 || padMax <=0 || padMax <= padMin)
    {
        fprintf(stderr, "Invalid padding values\n");
        return;
    }

    FCrypt::Encrypt out(outfile, (uint64_t)padMin, (uint64_t)padMax);
    if(!out.IsOk())
        return;

    uint8_t salt[SCRYPT_SALT];
    out.GetSalt(salt, SCRYPT_SALT);

    for(int i=0;i<n_files;i++)
    {
        printf("Password for %s (Min Length is 4): ", path[i]);
        char *pwd = getpass(""); 
        if(pwd == NULL || strlen(pwd) < 3)
        {
            pwd = getpass("Try Again: "); 
            if(pwd == NULL)
            {
                out.Discard();
                printf("Discarding. Bye.\n");
                return;
            }
        }

        FCrypt::Scrypt scrypt(pwd, strlen(pwd), salt, SCRYPT_SALT);
        EF_ZeroMem(pwd, strlen(pwd)); // leaking password length

        out.AddFile(scrypt, path[i]);
    }
}

void Utils::DecryptHelper(const char *file, const char *outfile)
{
    // TODO: check if outfile exists

    FCrypt::Decrypt decrypt(file, outfile);

    if(!decrypt.IsOk())
    {
        fprintf(stderr, "Error opening files\n");
        return;
    }

    const FileHdr& hdr = decrypt.GetHeader();

    char *pwd = getpass("Password: ");
    if(pwd == NULL || strlen(pwd) < 1)
        return;

    FCrypt::Scrypt scrypt(pwd, strlen(pwd), hdr.salt, SCRYPT_SALT);
    EF_ZeroMem(pwd, strlen(pwd));

    if(!decrypt.Run(scrypt))
        unlink(outfile);
}
    
} /* FCrypt */ 
