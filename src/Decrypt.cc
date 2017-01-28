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

#include "Decrypt.h"

namespace FCrypt
{

Decrypt::Decrypt(const char *infile, const char *outfile) : m_ok(false)
{ 
    assert(sizeof(Hdr) == 192); 
    assert(sizeof(Data) == AES::BLOCKSIZE); 

    m_infp = fopen(infile, "rb");
    m_outfp = fopen(outfile, "wb");

    if(m_infp)
    {
        int n = fread((uint8_t *) &m_hdr, sizeof(m_hdr), 1, m_infp);
        if(n == 1)
            m_ok = true;
    }
}

Decrypt::~Decrypt()
{
    if(m_infp) fclose(m_infp);
    if(m_outfp) fclose(m_outfp);
}

bool Decrypt::IsOk() const
{
    return m_infp && m_outfp && m_ok;
}

const FileHdr& Decrypt::GetHeader() const
{
    return m_hdr;
}

bool Decrypt::Run(const Scrypt& scrypt) const
{
    if(!m_infp || !m_outfp)
        return false;

    // TODO: fseek here

    // Header keys
    SecByteBlock akey = scrypt.GetAuthKey();
    SecByteBlock key  = scrypt.GetKey();
    SecByteBlock iv   = scrypt.GetIV();
    SecByteBlock salt = scrypt.GetSalt();

    HMAC<SHA512> mac = HMAC<SHA512>(akey.data(), akey.size());

    int n=0;

    Data fileData = {0, 0}; // "data" header
    const Hdr* ptr;
    uint8_t fileAESKey[AES::MAX_KEYLENGTH], fileAESIV[AES::BLOCKSIZE];

    do
    {
        ptr = &m_hdr.headers[n];
        CBC_Mode<AES>::Decryption hdrDec = 
            CBC_Mode<AES>::Decryption(key.data(), key.size(), iv.data());

        // Header MAC
        mac.Restart();
        mac.Update(ptr->AESKey, AES::MAX_KEYLENGTH);
        mac.Update(ptr->AESIV,  AES::BLOCKSIZE);
        mac.Update(ptr->data,   AES::BLOCKSIZE);
        uint8_t calcMAC[HMAC<SHA512>::DIGESTSIZE];
        mac.TruncatedFinal(calcMAC, HMAC<SHA512>::DIGESTSIZE);

        if(!memcmp(calcMAC, ptr->MACHdr, HMAC<SHA512>::DIGESTSIZE))
        {
            // Read encrypted keys
            hdrDec.ProcessData(fileAESKey, ptr->AESKey, AES::MAX_KEYLENGTH);
            hdrDec.ProcessData(fileAESIV, ptr->AESIV, AES::BLOCKSIZE);
            hdrDec.ProcessData((uint8_t *) &fileData, ptr->data, AES::BLOCKSIZE);
            break;
        }
    } while(++n < NUM_HEADERS);

    if(n == NUM_HEADERS)
    {
        fprintf(stderr, "Invalid key\n");
        return false;
    }

    fseek(m_infp, fileData.offset, SEEK_SET);

    CBC_Mode<AES>::Decryption fileDec = 
        CBC_Mode<AES>::Decryption(fileAESKey, AES::MAX_KEYLENGTH, fileAESIV);
    
    // Erase keys
    EF_ZeroMem(fileAESKey, sizeof(fileAESKey));
    EF_ZeroMem(fileAESIV, sizeof(fileAESIV));

    // Decrypt
    uint8_t pData[AES::BLOCKSIZE] = {0}, dData[AES::BLOCKSIZE] = {0};
    mac.Restart();
    for(size_t i = 0; i < fileData.size; i += AES::BLOCKSIZE)
    {
        assert(1 == fread(pData, AES::BLOCKSIZE, 1, m_infp));

        // MAC and Decrypt
        mac.Update(pData, AES::BLOCKSIZE);
        fileDec.ProcessData(dData, pData, AES::BLOCKSIZE);

        uint8_t bsize = AES::BLOCKSIZE;
        if(i + bsize >= fileData.size)
            bsize = fileData.size - i;

        fwrite(dData, bsize, 1, m_outfp);
    }

    EF_ZeroMem(pData, sizeof(pData));
    EF_ZeroMem(dData, sizeof(dData)); // useless

    uint8_t fileMac[HMAC<SHA512>::DIGESTSIZE];
    mac.TruncatedFinal(fileMac, HMAC<SHA512>::DIGESTSIZE);

    if(memcmp(fileMac, ptr->MACFile, HMAC<SHA512>::DIGESTSIZE))
    {
        fprintf(stderr, "File corrupted. Invalid MAC\n");
        return false;
    }

    fflush(m_outfp);
    printf("Extract OK\n");
    return true;
}
    
} /* FCrypt */ 
