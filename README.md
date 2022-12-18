# Trusted Core: Registration Authority 
A custom client designed to perform registration authority functions utilizing the Registration Authority Management Interface (RAMI) secure API.

## Prerequisites

- Bash
- OpenSSL
- Curl

## Installation

## Usage

This script is meant to be operated directly from CLI input; all options are specified inline.

**ECDSA Generation**
`./tcra.sh <input-file> ecdsa`

**ECDH Generation**
`./tcra.sh <input-file> ecdh`

**RSA Generation**
`./tcra.sh <input-file> rsa`

## License & Credits

### Author

**Tony Cavella** 
- <tony@cavella.com>
- <https://github.com/acavella/trustedcore-ra>

### License

MIT License

Copyright (c) 2022 Tony Cavella

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.