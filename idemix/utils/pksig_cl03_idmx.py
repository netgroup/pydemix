"""
Copyright (c) 2013 Antonio de la Piedra
 
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
  
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
   
You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

'''
Specification of the Identity Mixer Cryptographic Library 
 
| From: "IBM Research - Zurich"
| Published in: 2012
| Available from: https://prime.inf.tu-dresden.de/idemix/
| Notes: Modification over [CL03]: Scheme 4.3 (on page 13)

* type:           signature
* setting:        integer groups 

:Authors:    Antonio de la Piedra
:Date:       12/2013
 '''
import hashlib

from charm.core.math.integer import integer, random, randomPrime, randomBits
from charm.toolbox.PKSig import PKSig


def SHA1(bytes1):
    s1 = hashlib.new('sha1')
    s1.update(bytes1)
    return s1.digest()


def randomQR(n):
    return random(n) ** 2


debug = False


class Sig_CL03_Idmx(PKSig):
    """
    >>> from charm.toolbox.conversion import Conversion
    >>> pksig = Sig_CL03_Idmx()
    >>> p = integer(333437049425486136095925931727629203622119239282802038455917646172563395024265917241890473852501318262109839243221497854682815506880304349748481648877420618747530394310060738051284980323398797638078562462943477904211178707988798971266777314022673227003284335883622084916018185539789562312940907090712386355299)
    >>> q = integer(294092988306368388636535355362351220952777074915662080329740789451817968606482246364359892865057621298389179478994706465098262699509935804409002480293234947971872131356003427444279672200378079370695651721652248116723483318427208508192689675310517884904089979454005634358395042846262967137935407297336359215239)
    >>> (public_key, secret_key) = pksig.keygen(1024, p, q)
    >>> m = {}
    >>> j = 16
    >>> for i in range(1, j + 1): m[str(i)] = integer(SHA1(Conversion.IP2OS(random(public_key['N']))))
    >>> signature = pksig.sign(public_key, secret_key, m)
    >>> pksig.verify(public_key, m, signature)
    True
    """

    # lm = size of attributes // 256 bits according to p. 40
    # ln = size of RSA modulus // 2048 bits according to p. 40
    # l  = number of attributes // default = 16
    # lr = security parameter required in the proof of security of 
    #	   the credential system // 80 bits according to p. 40

    def __init__(self, lnin=2048, lmin=256, lrin=80, lin=16, loin=80, lein=597, secparam=1024):
        global ln, lm, le, l, lr, lo
        lo = loin
        lm = lmin
        le = lein
        l = lin
        ln = lnin
        lr = lrin

    def keygen(self, p, q):

        N = p * q

        Xz = integer(random(N))
        Xr = {}

        for i in range(1, l + 1):
            Xr[str(i)] = integer(random(N))

        S = randomQR(N)
        Z = S ** Xz

        R = {}

        for i in range(1, l + 1):
            R[str(i)] = S ** Xr[str(i)]

        pk = {'N': N, 'R': R, 'S': S, 'Z': Z}
        sk = {'p': p, 'q': q}

        return (pk, sk)

    def sign(self, pk, sk, m, v=0, u=0, e=0):

        if (e == 0):
            e = randomPrime(le)

        lv = ln + lm + lr

        if (v == 0):
            v = integer(randomBits(lv))

        R = pk['R']

        Cx = 1 % pk['N']

        for i in range(1, len(m) + 1):
            Cx = Cx * (R[str(i)] ** m[str(i)])

        phi_N = (sk['p'] - 1) * (sk['q'] - 1)
        e2 = e % phi_N

        if (u != 0):
            u = u % pk['N']
            Cx = Cx * u

        q = pk['Z'] / (Cx * (pk['S'] ** v)) % pk['N']
        a = q ** (e2 ** -1) % pk['N']

        sig = {'A': a, 'Q': q, 'e': e, 'v': v}

        return sig

    def verify(self, pk, m, sig):
        if debug: print("\nVERIFY\n\n")

        lhs = pk['Z']

        R = pk['R']

        Cx = 1 % pk['N']

        for i in range(1, len(m) + 1):
            Cx = Cx * (R[str(i)] ** m[str(i)])

        rhs = (Cx * (sig['A'] ** sig['e']) * (pk['S']) ** sig['v']) % pk['N']

        if (sig['e'] <= 2 ** (le - 1) or sig['e'] >= 2 ** (le)):
            return False

        if (lhs == rhs):
            return True

        return False

    def randomize(self, pk, sig):

        rA = integer(randomBits(ln + lo))
        aP = (sig['A'] * (pk['S'] ** rA)) % pk['N']
        vP = sig['v'] - (sig['e'] * rA)
        eP = sig['e'] - (2 ** (le - 1))

        sigP = {'A': aP, 'e': eP, 'v': vP}

        return sigP

    def randSign(self, pk, m, sig):
        print "TODO"
