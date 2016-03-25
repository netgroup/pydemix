"""
Copyright (c) 2013-2016 Antonio de la Piedra, Alberto Caponi, Claudio Pisa
Original code from Antonio de la Piedra: https://github.com/adelapie/irma_phase_2/tree/master/terminal

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

import hashlib

from charm.core.math.integer import integer, isPrime, random, randomPrime, randomBits
from charm.toolbox.conversion import Conversion
from utils.commit_df02 import CM_DF02

from idemix.settings import lm, lo, le, lv
from idemix.utils.pksig_cl03_idmx import Sig_CL03_Idmx


class Issuer:
    'Idemix issuer'

    def __init__(self, l, p, q, secparam, context):
        self.secparam = secparam
        self.l = l
        self.context = context

        self.pksig = 0

        if (p == 0):
            pprime = randomPrime(secparam)
            while (not isPrime(2 * pprime + 1)):
                pprime = randomPrime(secparam)

            self.p = integer(2 * pprime + 1)
        else:
            self.p = p

        if (q == 0):
            qprime = randomPrime(secparam)
            while (not isPrime(2 * qprime + 1)):
                qprime = randomPrime(secparam)

            self.q = integer(2 * qprime + 1)
        else:
            self.q = q

    def gen_key_pair(self):

        self.pk_i = {}
        self.sk_i = {}

        self.pksig = Sig_CL03_Idmx(lin=self.l)
        (self.pk_i, self.sk_i) = self.pksig.keygen(self.p, self.q)

        self.S = self.pk_i['S']
        self.Z = self.pk_i['Z']
        self.R = self.pk_i['R']
        self.N = self.pk_i['N']

        self.Ro = self.pk_i['S'] ** integer(random(self.pk_i['N']))
        self.pk_i['Ro'] = self.Ro

        return (self.pk_i, self.sk_i)

    def set_key_pair(self, n_pk_i, n_sk_i):

        self.pk_i = n_pk_i
        self.sk_i = n_sk_i

        self.l = len(n_pk_i['R'])

        self.pksig = Sig_CL03_Idmx(lin=self.l)

    def signAttributes(self, attr):
        self.signature = self.pksig.sign(self.pk_i, self.sk_i, attr, 0, 0, 0)

        return self.signature

    def signAttributesLong(self, attr, vx, ux, ex):
        self.signature = self.pksig.sign(self.pk_i, self.sk_i, attr, v=vx, u=ux, e=ex)

        return self.signature

    def verifySignature(self, attr, signature):
        return self.pksig.verify(self.pk_i, attr, signature)

    def selfTest(self):
        mt = {}

        for i in range(1, self.l + 1):
            mt[str(i)] = integer(randomBits(lm)) % self.pk_i['N']

        signature = self.pksig.sign(self.pk_i, self.sk_i, mt)

        return self.verifySignature(mt, signature)

    def round_0(self):
        self.n1 = integer(randomBits(lo))

        return self.n1

    def __verify_p1(self, p1):

        df02_commit = CM_DF02()
        pk_commit = {'S': self.pk_i['S'], 'Z': self.pk_i['Ro'], 'N': self.pk_i['N']}

        sHat = p1['sHat']
        vPrimeHat = p1['vPrimeHat']
        (cA, vPrimeHat) = df02_commit.commit(pk_commit, sHat, 0, vPrimeHat)

        U = p1['U'] % self.pk_i['N']
        c = p1['c']

        Uhat = cA * (U ** (-1 * c))

        s2 = hashlib.new('sha256')

        s2.update(Conversion.IP2OS(self.context))
        s2.update(Conversion.IP2OS(U))
        s2.update(Conversion.IP2OS(Uhat))
        s2.update(Conversion.IP2OS(self.n1))

        cHat = integer(s2.digest())

        return c == cHat

    def round_2(self, U, p1, attr, n2):

        if self.__verify_p1(p1):
            pass
            # print "P1 verified"
        else:
            return None

        e = randomPrime(le)

        vTilde = integer(randomBits(lv - 1))
        vPrimePrime = (2 ** (lv - 1)) + vTilde

        R = self.pk_i['R']
        Cx = 1 % self.pk_i['N']

        for i in range(1, len(attr) + 1):
            Cx = Cx * (R[str(i)] ** attr[str(i)])

        sigA = self.signAttributesLong(attr, vPrimePrime, U, e)

        A = sigA['A']
        Q = sigA['Q']

        phi_N = (self.sk_i['p'] - 1) * (self.sk_i['q'] - 1)
        e2 = e % phi_N

        r = randomPrime(le)
        Atilde = (Q ** r) % self.pk_i['N']

        s3 = hashlib.new('sha256')

        s3.update(Conversion.IP2OS(self.context))
        s3.update(Conversion.IP2OS(Q))
        s3.update(Conversion.IP2OS(A))
        s3.update(Conversion.IP2OS(n2))
        s3.update(Conversion.IP2OS(Atilde))

        cPrime = integer(s3.digest())
        e2Prime = e2 ** - 1

        Se = r - (cPrime * integer(e2Prime))

        signature = {'A': A, 'e': e, 'vPrimePrime': vPrimePrime}
        P2 = {'Se': Se, 'cPrime': cPrime}

        print signature
        print P2
        return signature, P2
