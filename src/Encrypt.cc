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

#include "Encrypt.h"

extern AutoSeededRandomPool rnd;

namespace FCrypt
{

Encrypt::Encrypt(const char *path, uint64_t padMin, uint64_t padMax) : 
    m_path(path)
{
    assert(sizeof(Hdr) == 192); 
    assert(sizeof(Data) == AES::BLOCKSIZE); 

    m_padmin = padMin;
    m_padmax = padMax;

    m_fp = fopen(path, "wb");
    if(m_fp == NULL)
    {
        fprintf(stderr, "Cannot open %s\n", path);
        m_ok = false;
    } 
    else 
    {
        for(int i=0;i<NUM_HEADERS;i++)
            m_used_slots[i] = false;

        // write random data in the header
        rnd.GenerateBlock((uint8_t *) &m_hdr, sizeof(m_hdr));

        // allocate space in the file for the header
        uint8_t temp[sizeof(FileHdr)] = {0};
        fseek(m_fp, 0, SEEK_SET);
        fwrite(temp, sizeof(FileHdr), 1, m_fp);
        m_ok = true;
    }
}

Encrypt::~Encrypt() 
{
    if(m_ok)
    {
        WriteHeader();
        fclose(m_fp);
    }

    EF_ZeroMem(m_used_slots, sizeof(m_used_slots));
}

bool Encrypt::IsOk() const
{
    return m_ok;
}

void Encrypt::Discard()
{
    if(m_ok)
    {
        fclose(m_fp);
        unlink(m_path);
        m_ok = false;
    }
}

void Encrypt::GetSalt(uint8_t *out, size_t outlen) const
{
    assert(outlen == SCRYPT_SALT);
    memcpy(out, m_hdr.salt, SCRYPT_SALT);
}


void Encrypt::WriteHeader()
{
    fseek(m_fp, 0, SEEK_SET);
    fwrite((uint8_t *) &m_hdr, sizeof(FileHdr), 1, m_fp);
}

void Encrypt::WritePadding()
{
    uint32_t qty = rnd.GenerateWord32(m_padmin, m_padmax);
    uint8_t *padding = new uint8_t[qty];

    rnd.GenerateBlock(padding, qty);
    fwrite(padding, qty, 1, m_fp);
    delete[] padding;
}

// add a file
bool Encrypt::AddFile(const Scrypt& scrypt, const char *path)
{
    if(!m_ok)
        return false;

    FILE * in_fp = fopen(path, "rb");
    if(!in_fp)
        return false;

    fseek(in_fp, 0, SEEK_END);
    int64_t tempLen = ftell(in_fp);
    if(tempLen < 0)
    {
        fprintf(stderr, "%s has invalid size (%ld)", path, tempLen);
        fclose(in_fp);
        return false;
    }
    uint64_t len = tempLen;

    fseek(in_fp, 0, SEEK_SET);

    // check for empty slots
    int n;
    for(n=0;n<NUM_HEADERS;n++)
        if(m_used_slots[n] == false)
            break;
    assert(n < NUM_HEADERS);

    // Choose a random slot
    do {
        n = rnd.GenerateByte() % NUM_HEADERS;
    } while(m_used_slots[n]);
    m_used_slots[n] = true;

    uint8_t fileAESKey[AES::MAX_KEYLENGTH], fileAESIV[AES::BLOCKSIZE];

    // Header keys
    SecByteBlock akey = scrypt.GetAuthKey();
    SecByteBlock key  = scrypt.GetKey();
    SecByteBlock iv   = scrypt.GetIV();
    SecByteBlock salt = scrypt.GetSalt();

    assert(0 == memcmp(salt.data(), m_hdr.salt, SCRYPT_SALT));

    // Data keys
    rnd.GenerateBlock(fileAESKey, AES::MAX_KEYLENGTH);
    rnd.GenerateBlock(fileAESIV, AES::BLOCKSIZE);
    
    HMAC<SHA512> mac = HMAC<SHA512>(akey.data(), akey.size());

    CBC_Mode<AES>::Encryption hdrEnc = 
        CBC_Mode<AES>::Encryption(key.data(), key.size(), iv.data());

    CBC_Mode<AES>::Encryption fileEnc = 
        CBC_Mode<AES>::Encryption(fileAESKey, AES::MAX_KEYLENGTH, fileAESIV);

    WritePadding();

    Hdr *ptr = &m_hdr.headers[n];
    int64_t curOutPos = ftell(m_fp);
    assert(curOutPos > 0);
    Data fileData = {(uint64_t) curOutPos, (uint64_t)len}; // "data" header

    // Encrypt header
    hdrEnc.ProcessData(ptr->AESKey, fileAESKey, AES::MAX_KEYLENGTH);
    hdrEnc.ProcessData(ptr->AESIV, fileAESIV, AES::BLOCKSIZE);
    hdrEnc.ProcessData(ptr->data, (const uint8_t *)&fileData, AES::BLOCKSIZE);

    // Erase keys
    EF_ZeroMem(fileAESKey, sizeof(fileAESKey));
    EF_ZeroMem(fileAESIV, sizeof(fileAESIV));
    
    // Calc Header MAC (EtM)
    mac.Restart();
    mac.Update(ptr->AESKey, AES::MAX_KEYLENGTH);
    mac.Update(ptr->AESIV, AES::BLOCKSIZE);
    mac.Update(ptr->data, AES::BLOCKSIZE);
    mac.TruncatedFinal(ptr->MACHdr, HMAC<SHA512>::DIGESTSIZE);

    uint8_t pData[AES::BLOCKSIZE], eData[AES::BLOCKSIZE];
    mac.Restart();
    for(size_t i = 0; i < len; i += AES::BLOCKSIZE)
    {
        uint8_t bsize = AES::BLOCKSIZE;
        if(i + AES::BLOCKSIZE >= len)
            bsize = len - i;

        assert(1 == fread(pData, bsize, 1, in_fp));

        // Encrypt Then MAC
        fileEnc.ProcessData(eData, pData, AES::BLOCKSIZE);
        mac.Update(eData, AES::BLOCKSIZE);

        fwrite(eData, AES::BLOCKSIZE, 1, m_fp);
    }

    EF_ZeroMem(pData, sizeof(pData));
    EF_ZeroMem(eData, sizeof(eData)); // useless

    mac.TruncatedFinal(ptr->MACFile, HMAC<SHA512>::DIGESTSIZE);
    fclose(in_fp);
    WritePadding();
    return true;
}

    
} /* FCrypt */ 
