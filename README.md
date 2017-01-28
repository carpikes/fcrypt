# fcrypt

#### This is an experimental software and might contain bugs. Use at your own risk.

fcrypt is a file encryption tool.

## Features

* Scrypt as Key Derivation Function.
* Encryption using AES256-CBC and authentication using HMAC-SHA512.
* Multiple files (16, configurable in `src/Config.h` in one package, one password per file.
* A package is indistinguishable from /dev/urandom output.
* There's no way to know how many and which files are encrypted in a package without knowing the password of each single file.

## Installation

```
git clone --recursive https://github.com/carpikes/fcrypt.git
cd fcrypt
make
sudo make install
```

## Usage

Here are some examples:

#### Encryption

The following command encrypts `file1.jpg`, `file2.txt`, `file3.png` with
different password (asked after pressing enter) and creates the packed file 
`encfile.out`.

```
fcrypt e encfile.out file1.jpg file2.txt file3.png
```

#### Decryption

The following command extracts a file and saves it as `photo1.png`. 
The extracted file is chosen w.r.t. the typed password.

```
fcrypt d encfile.out photo1.png
```

## Known Bugs

* Do not use the same key for different files in a single package

## File Format

This section explains the format of an encrypted file (called "package").
fcrypt aims to make the package indistinguishable from random data, so every
field (if not used) is filled with random data.

An encrypted file has the following macro-structure:

```
[SCRYPT_SALT]
[HDR1][HDR2][...][HDR16]
[DATA]
```

`[DATA]` depends on how many files are encrypted in the package. 
It has a structure like this:

```
[RANDOM_DATA_1]
[FILE1]
[RANDOM_DATA_2]
[FILE2]
...
[RANDOM_DATA_N]
[FILEN]
[RANDOM_DATA_N+1]
```

Here's a brief explanation of each field.

`[RANDOM_DATA_X]` is a block containing random bytes with a length from 1KB 
to 10KB (by default). 
The range can be modified using `<padMin>` and `<padMax>` arguments.

`[SCRYPT_SALT]` is generated randomly when the file is created and is in
common between all the passwords.

There are 16 (by default) `[HDRX]`. Each one contains infos and keys for an
encrypted file. Each `[HDRX]` is encrypted using AES256-CBC  with a key derived
(using Scrypt) from the used password.

The internal structure of `[HDRX]` is defined in `src/Common.h` and is called
`struct Hdr`. 

Here's a more compact representation:
```
[1 (FILE) AES Key]
[2 (FILE) AES IV ]
[3 OFFSET]
[4 SIZE]
[5 MAC of 1,2,3,4]
[6 file MAC]
```

Fields (1) to (4) are encrypted using using AES256-CBC with the key + iv 
derived from the input password. 

MACs in fields (5) and (6) are calculated after encrypting the corresponding
blocks (Encrypt then MAC). The used key is the same and it's derived
from the input password.

MAC (6) is applied on the whole file.

#### Scrypt

Scrypt is used to derive 80 bytes from the password, which are used for:

* [32 bytes] HDR AES Key
* [16 bytes] HDR AES IV
* [32 bytes] MAC Key

By default, Scrypt uses these parameters `N = (1 << 20)`, `R = 16`, `P = 1`.


#### Pipeline

fcrypt implements the following pipeline:

##### Encryption

```
1. Generate a salt
2. Write all Zeros in the output file where will be th header.
3. Allocate the header in ram and write random data in it.
4. For each file
    a. Generate random AES Key + IV, encrypt that file and MAC it.
    b. Find a random free slot
    c. Mark that slot as used (in ram, in a separate array)
    d. Write encrypted HDR (in ram) and calculate HDR mac
    e. Write padding(random data) before the file
    f. Encrypt the file, calculate the MAC and write it in the output file
    g. Write padding(random data) after the file
5. At last, seek to the beginning of the file and write all headers
```

##### Decryption

```
1. Type the password
2. Read first 32 bytes and use them as Scrypt SALT
3. Password -> Scrypt -> { AESKey, AESIV, MACKey }
4. Decrypt each one of the 16 HDRs and check MACs.
5. If there's a match, check file MAC and decrypt it.
```

## License

```
This software is released under MIT license.
Copyright (c) 2017 Alain Carlucci

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
```
