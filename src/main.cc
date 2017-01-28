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

#include "Common.h"
#include "Utils.h"

AutoSeededRandomPool rnd;

using FCrypt::Utils;

void Usage(char *name)
{
    printf("Usage:\n"
           " %s e <outfile> <file1> [... <fileN>] \t\t\t"
           " Encrypt with default padding\n"

           " %s E <PadMin> <PadMax> <outfile> <file1> [... <fileN>] \t"
           " Encrypt with custom padding (in KB!)\n"

           " %s d <file> <outfile>\t\t\t\t\t Decrypt and unpack a file\n", 
           name, name, name);
}

int main(int argc, char *argv[])
{
    int64_t padMin, padMax;
    if(argc < 3 || strlen(argv[1]) != 1)
    {
        Usage(argv[0]);
        return -1;
    }

    switch(argv[1][0])
    {
        case 'e':
            if(argc < 4) 
            {
                Usage(argv[0]);
                return -1;
            }

            Utils::EncryptHelper(argc - 3, (const char **) &argv[3], argv[2]);
            break;
        case 'E':
            if(argc < 6) 
            {
                Usage(argv[0]);
                return -1;
            }

            padMin = atol(argv[2]) * 1024;
            padMax = atol(argv[3]) * 1024;

            if(padMax <= padMin || padMin < 1)
            {
                fprintf(stderr, "Invalid padding\n");
                return -1;
            }

            Utils::EncryptHelper(argc - 5, (const char **) &argv[5], argv[4], 
                                 padMin, padMax);
            break;
        case 'd':
            Utils::DecryptHelper(argv[2], argv[3]); 
            break;
        default:
            Usage(argv[0]);
            return -1;
    }

    return 0;
}
