## Python PKCS#5 v2.0 PBKDF2 Module


This module implements the password-based key derivation function, PBKDF2,
specified in `RSA PKCS#5 v2.0 <http://www.rsa.com/rsalabs/node.asp?id=2127>`
and `>http://www.ietf.org/rfc/rfc2898.txt>`.

Supports PBKDF2-HMAC-SHA1, PBKDF2-HMAC-SHA256 and PBKDF2-HMAC-SHA512.

### Example PBKDF2 usage

```python
from pbkdf2 import PBKDF2
from Crypto.Cipher import AES
import os

salt = os.urandom(8)    # 64-bit salt
key = PBKDF2("This passphrase is a secret.", salt).read(32) # 256-bit key
iv = os.urandom(16)     # 128-bit IV
cipher = AES.new(key, AES.MODE_CBC, iv)
# ...
```

### Example crypt() usage

The used digest module and the required number of rounds are detected 
and used from the second argument to `crypt`, if it is a valid crypt hash
(meaning it starts with `$p5k2$`)

```python
from pbkdf2 import crypt
pwhash = crypt("secret")
alleged_pw = raw_input("Enter password: ")
if pwhash == crypt(alleged_pw, pwhash):
	print "Password good"
else:
	print "Invalid password"
```


### Example crypt() output

```python
>>> from pbkdf2 import crypt
# A salt will be generated if none if provided
>>> crypt("secret")
'$p5k2$sha1$1000$liUvxXY9$jB/APCukN8TnQFI6BfBkOLdP6z0='
# The default number of iterations is 4096
>>> crypt("secret", "XXXXXXXX")
'$p5k2$sha1$1000$XXXXXXXX$EqpMjdbd336OVqk/JK0Qu932NWM='
# 10000 iterations
>>> crypt("secret", "XXXXXXXX", 10000)
'$p5k2$sha1$2710$XXXXXXXX$la/Sagg42hj7VeDaMKYI4xzkdv0='
>>> crypt("spam", iterations=10000)
'$p5k2$sha1$2710$/ZSv3AF8$6SzmraqNbhxGAf.Ptr8YbZtvvn8='
# Hash with SHA256 or SHA512
>>> from hashlib import sha256, sha512
>>> crypt("secret", digestmodule=sha256)
'$p5k2$sha256$1000$bYYWLg0q$rUmVVQC9JN7fKzSRK6xpCuW/hqeZqbWkv.34ytwWSzA='
>>> crypt("secret", digestmodule=sha512)
'$p5k2$sha512$1000$LnGo.ypX$EBKREhDKlYVb69HVXjrzxYa39GRhelSSGlg6Isb.amoJTt/fh8ymUY9sa5gvl2EEk1YCjJJ43xWarTleyrb9Cg=='
# Make the computation more expensive by increasing iterations
>>> crypt("secret", iterations=32768, digestmodule=sha512)
'$p5k2$sha512$8000$KUDIEJO6$D2AJp3ahJK.ki1Z33i.yz4PrrDMK3A8THVgbUl6GDr7LZqAVdrSeQAY.1AkZsO6ZoD4gNdEsl9q2qZEubHAzpQ=='
```

### Resources

Homepage
    https://www.dlitz.net/software/python-pbkdf2/

Source Code
    https://github.com/dlitz/python-pbkdf2/

PyPI package name
    `pbkdf2 <http://pypi.python.org/pypi/pbkdf2>`_

### License
Copyright (C) 2007-2011 Dwayne C. Litzenberger <dlitz@dlitz.net>

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
