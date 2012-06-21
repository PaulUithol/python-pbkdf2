#!/usr/bin/python
# -*- coding: ascii -*-

import unittest
from pbkdf2 import PBKDF2, crypt, b, SHA1, SHA256, SHA512

from binascii import hexlify, unhexlify
import math
import sys


class TestPBKDF2(unittest.TestCase):
    def test_pbkdf2(self):
        """Module self-test"""
        from binascii import a2b_hex as _a2b_hex
        def a2b_hex(s):
            return _a2b_hex(b(s))

        #
        # Test vectors from RFC 3962
        #

        # Test 1
        result = PBKDF2("password", "ATHENA.MIT.EDUraeburn", 1).read(16)
        expected = a2b_hex("cdedb5281bb2f801565a1122b2563515")
        self.assertEqual(expected, result)

        # Test 2
        result = PBKDF2("password", "ATHENA.MIT.EDUraeburn", 1200).hexread(32)
        expected = ("5c08eb61fdf71e4e4ec3cf6ba1f5512b"
                    "a7e52ddbc5e5142f708a31e2e62b1e13")
        self.assertEqual(expected, result)

        # Test 3
        result = PBKDF2("X"*64, "pass phrase equals block size", 1200).hexread(32)
        expected = ("139c30c0966bc32ba55fdbf212530ac9"
                    "c5ec59f1a452f5cc9ad940fea0598ed1")
        self.assertEqual(expected, result)

        # Test 4
        result = PBKDF2("X"*65, "pass phrase exceeds block size", 1200).hexread(32)
        expected = ("9ccad6d468770cd51b10e6a68721be61"
                    "1a8b4d282601db3b36be9246915ec82a")
        self.assertEqual(expected, result)


        #
        # Test vectors for PBKDF2 HMAC-SHA1, from RFC 6070
        # http://tools.ietf.org/html/rfc6070
        #

        result = PBKDF2('password', 'salt', 1, SHA1).hexread(20)
        expected = '0c60c80f961f0e71f3a9b524af6012062fe037a6'
        self.assertEqual(expected, result)


        #
        # Test vectors for PBKDF2 HMAC-SHA256
        # http://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors
        #

        result = PBKDF2('password', 'salt', 1, SHA256).hexread(32)
        expected = '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b'
        self.assertEqual(expected, result)

        result = PBKDF2('password', 'salt', 2, SHA256).hexread(32)
        expected = 'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43'
        self.assertEqual(expected, result)

        result = PBKDF2('password', 'salt', 4096, SHA256).hexread(32)
        expected = 'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a'
        self.assertEqual(expected, result)

        # This one takes a bit of time, but it's been verified. Run it when you have some to spare.
#        result = PBKDF2('password', 'salt', 16777216, SHA256).hexread(32)
#        expected = 'cf81c66fe8cfc04d1f31ecb65dab4089f7f179e89b3b0bcb17ad10e3ac6eba46'
#        self.assertEqual(expected, result)

        result = PBKDF2('passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, SHA256).hexread(40)
        expected = '348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9'
        self.assertEqual(expected, result)

        result = PBKDF2('pass\0word', 'sa\0lt', 4096, SHA256).hexread(16)
        expected = '89b69d0516f829893c696226650a8687'
        self.assertEqual(expected, result)


        #
        # Still missing: test vectors for PBKDF2 HMAC-SHA512, except for a single one found at
        # http://code.google.com/p/passlib/source/browse/passlib/tests/test_utils_crypto.py,
        # which credits http://grub.enbug.org/Authentication.
        #
        salt = unhexlify( '9290F727ED06C38BA4549EF7DE25CF5642659211B7FC076F2D28FEFD71'
                          '784BB8D8F6FB244A8CC5C06240631B97008565A120764C0EE9C2CB0073'
                          '994D79080136' )
        result = PBKDF2('hello', salt, 10000, SHA512).hexread(64)
        expected = ('887CFF169EA8335235D8004242AA7D6187A41E3187DF0CE14E256D85ED'
                    '97A97357AAA8FF0A3871AB9EEFF458392F462F495487387F685B7472FC'
                    '6C29E293F0A0').lower()
        self.assertEqual(expected, result)


        #
        # Other test vectors
        #

        # Chunked read
        f = PBKDF2("kickstart", "workbench", 256)
        result = f.read(17)
        result += f.read(17)
        result += f.read(1)
        result += f.read(2)
        result += f.read(3)
        expected = PBKDF2("kickstart", "workbench", 256).read(40)
        self.assertEqual(expected, result)


    def test_crypt(self):
        result = crypt("secret")
        self.assertEqual(result[:6], "$p5k2$")

        # Default algorithm is `sha1`; default number of rounds is 4096
        result = crypt("secret", "XXXXXXXX")
        expected = '$p5k2$sha1$1000$XXXXXXXX$'
        self.assertEqual(expected, result[:25])

        # 400 iterations
        result = crypt("secret", "XXXXXXXX", 400)
        expected = '$p5k2$sha1$190$XXXXXXXX$'
        self.assertEqual(expected, result[:24])

        # 400 iterations (keyword argument)
        result = crypt("spam", "FRsH3HJB", iterations=400)
        expected = '$p5k2$sha1$190$FRsH3HJB$'
        self.assertEqual(expected, result[:24])

        # 1000 iterations
        result = crypt("spam", "H0NX9mT/", iterations=1000)
        expected = '$p5k2$sha1$3e8$H0NX9mT/$'
        self.assertEqual(expected, result[:24])

        # 1000 iterations (iterations count taken from salt parameter)
        expected = '$p5k2$sha1$3e8$H0NX9mT/$ih6FhDyRXAaEN4UXk50pNsZP/nU='
        result = crypt("spam", expected)
        self.assertEqual(expected, result)

        # Feed the result back in; both hashes should match, as the algo and iteration count are taken from the expected hash
        expected = crypt("spam")
        result = crypt( "spam", expected )
        self.assertEqual(expected, result)

        # ...and this one shouldn't match
        expected = crypt("password")
        result = crypt( "passwd", expected )
        self.assertNotEqual(expected, result)

        #
        # SHA256
        #
        result = crypt("spam", "XXXXXXXX", digestmodule=SHA256)
        expected = '$p5k2$sha256$1000$XXXXXXXX$'
        self.assertEqual(expected, result[:27])

        # Feed the result back in; both hashes should match, as the algo and iteration count are taken from the expected hash
        expected = crypt("spam", digestmodule=SHA256)
        result = crypt( "spam", expected )
        self.assertEqual(expected, result)

        # ...and this one shouldn't match
        expected = crypt("password", digestmodule=SHA256)
        result = crypt( "passwd", expected )
        self.assertNotEqual(expected, result)

        #
        # SHA512
        #
        result = crypt("spam", "XXXXXXXX", digestmodule=SHA512)
        expected = '$p5k2$sha512$1000$XXXXXXXX$'
        self.assertEqual(expected, result[:27])

        # Feed the result back in; both hashes should match, as the algo and iteration count are taken from the expected hash
        expected = crypt("spam", digestmodule=SHA512)
        result = crypt( "spam", expected )
        self.assertEqual(expected, result)

        # ...and this one shouldn't match
        expected = crypt("password", digestmodule=SHA512)
        result = crypt( "passwd", expected )
        self.assertNotEqual(expected, result)



        #
        # crypt() test vectors
        #

        # crypt 1
        result = crypt("cloadm", "exec", iterations=400)
        expected = '$p5k2$sha1$190$exec$jkxkBaZJp.nvBg4WV7BW96972fE='
        self.assertEqual(expected, result)

        # crypt 2
        result = crypt("gnu", '$p5k2$sha1$c$u9HvcT4d$.....')
        expected = '$p5k2$sha1$c$u9HvcT4d$iDgHukD37rW7UgWCS24lnNRjO3c='
        self.assertEqual(expected, result)

        # crypt 3
        result = crypt("dcl", "tUsch7fU", iterations=13)
        expected = "$p5k2$sha1$d$tUsch7fU$.8H47sUSBmz0PDHbKfXHkjDDboo="
        self.assertEqual(expected, result)

        # crypt 3, SHA256
        result = crypt("dcl", "tUsch7fU", iterations=13, digestmodule=SHA256)
        expected = "$p5k2$sha256$d$tUsch7fU$A1I2wQdnQb28U7UD4aaxwuFL5IFj.AWLngbwVLHOkVo="
        self.assertEqual(expected, result)

        # crypt3, SHA512
        result = crypt("dcl", "tUsch7fU", iterations=13, digestmodule=SHA512)
        expected = "$p5k2$sha512$d$tUsch7fU$GM78GODhPDWxODRnH4/L9lGnTqMgmsYJEROltbxUVquPm1P9qmbRkQM1KuFOf6QEBXX20eMGwYRmDrFLHDyn6Q=="
        self.assertEqual(expected, result)

        # crypt 4 (unicode)
        result = crypt(b('\xce\x99\xcf\x89\xce\xb1\xce\xbd\xce\xbd\xce\xb7\xcf\x82').decode('utf-8'),
            '$p5k2$sha1$3e8$KosHgqNo$jJ.gcxXLu6COVzAlz5SRvAqZTd8=')
        expected = '$p5k2$sha1$3e8$KosHgqNo$jJ.gcxXLu6COVzAlz5SRvAqZTd8='
        self.assertEqual(expected, result)

        # crypt 5 (UTF-8 bytes)
        result = crypt(b('\xce\x99\xcf\x89\xce\xb1\xce\xbd\xce\xbd\xce\xb7\xcf\x82'),
            '$p5k2$sha1$3e8$KosHgqNo$jJ.gcxXLu6COVzAlz5SRvAqZTd8=')
        expected = '$p5k2$sha1$3e8$KosHgqNo$jJ.gcxXLu6COVzAlz5SRvAqZTd8='
        self.assertEqual(expected, result)


if __name__ == '__main__':
    unittest.main()

# vim:set ts=4 sw=4 sts=4 expandtab:
