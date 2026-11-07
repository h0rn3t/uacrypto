# Third-party notices

## cryptonite

The DSTU 7624 modes of `kalyna` and the GOST 28147-89 modes and S-box tables of `gost28147`
follow the certified cryptonite library of PrivatBank IT
(<https://github.com/privat-it/cryptonite>, `src/cryptonite/c/dstu7624.c`,
`src/cryptonite/c/gost28147.c`), the key files of `pki/pkcs12.go` follow its storage
(`src/storage/c/file/pkcs5.c`, `pkcs8.c`, `pkcs12_utils_internal.c`), and
`kalyna/testdata/dstu7624.json`, the vectors of `gost28147/modes_test.go` and
`pki/testdata/iit-123456.pfx` (`src/storageUtest/resources/pkcs12_by_iit(123456).pfx`) come from
its tests (`src/cryptoniteAtest`, `src/cryptoniteUtest`, `src/storageUtest`), under this license:

```text
Copyright 2016 PrivatBank IT <acsk@privatbank.ua>

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## jkurwa

`pki/testdata/jkurwa-store-a040.dat`, `jkurwa-key40a0.der` and `jkurwa-self-signed-enc-40a0.cer`
are `STORE_A040.dat`, `Key40A0.pem` (decoded from PEM) and `SELF_SIGNED_ENC_40A0.cer` from the tests
of jkurwa by Ilya Petrov (<https://github.com/dstucrypt/jkurwa>, `test/data`), version 1.22.9,
published under the BSD license. The Key-6.dat and JKS readers of `pki/keystore.go` follow those of
jkurwa (`lib/spec/keystore.js`, `lib/util/load.js`), gost89 0.1.12 (`lib/compat.js`, `lib/util.js`)
and jksreader 1.0.0 (<https://github.com/dstucrypt/jksreader>), all of dstucrypt under the BSD
license.

## li0ard/strumok

The ciphertext in `strumok/strumok_test.go` (`TestEncrypt`) comes from `tests/encryption.test.ts` of
@li0ard/strumok by Nikolai Konovalov (<https://github.com/li0ard/strumok>, commit afcf9d1), and the
reduction constants `alphaMul` and `alphaInvMul` of `strumok/strumok.go` are entries of its tables
`ALPHA_MUL` and `ALPHA_MUL_INV`, under this license:

```text
MIT License

Copyright (c) 2025 Nikolai Konovalov

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
