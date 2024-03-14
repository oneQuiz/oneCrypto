# -*- coding: utf-8 -*-
#
# ===================================================================
# The contents of this file are dedicated to the public domain.  To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================

"""oneCrypto, a Python Cryptography Rookie Toolkit of Chinese National Standard

Subpackages:

oneCrypto.common
 Common mathematical and string's coding algorithms
Crypto.prime
 Algorithms related to primes and strong primes
Crypto.ECC
 Elliptic-curve cryptography's algorithms
Crypto.SM2
 A public key encryption standard of Chinese National Standard
 (Signature algorithm, encryption algorithm)
Crypto.SM3
 A cryptographic hash function used in the Chinese National Standard
Crypto.SM4
 A block cipher used in the Chinese National Standard
"""
__all__ = ['common', 'ECC', 'prime', 'SM2', 'SM3', 'SM4']

__version__ = '0.0.0'     # See also below and setup.py
__revision__ = "$Id$"