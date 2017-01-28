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

#ifndef FCRYPT_UTILS_H
#define FCRYPT_UTILS_H

#include "Common.h"

namespace FCrypt
{

class Utils
{
public:

    // Encrypt & pack a list of files in a file
    static void EncryptHelper(int n_files, const char *path[], char *outfile, 
                              int64_t padMin = DEFAULT_PADDING_MIN, 
                              int64_t padMax = DEFAULT_PADDING_MAX);

    // Decrypt and extract a file
    static void DecryptHelper(const char *file, const char *outfile);

private:
    Utils(const Utils&) = delete;
    Utils(Utils&&) = delete;
    Utils& operator=(const Utils&) & = delete;
    Utils& operator=(Utils&&) & = delete;
    virtual ~Utils() { }
    Utils() { }
};
    
} /* FCrypt */ 

#endif /* ifndef FCRYPT_UTILS_H */
