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
| Notes: Schemes 6.1 (on page 17) and 6.2.3 (on page 24).

* type:           issuance and verification protocol
* setting:        integer groups 

:Authors:    Alberto Caponi, Claudio Pisa
:Date:       02/2016
 '''
import hashlib

from charm.core.math.integer import integer, isPrime, random, randomPrime, randomBits
from charm.toolbox.conversion import Conversion
from pyasn1.codec.ber import encoder as ber_encoder
from pyasn1.type import univ

from commit_df02 import CM_DF02

# constants

global lm, ln, lo, lh, le, l, lv, lePrime

lePrime = 120  # size of the interval the e valus are taken from
le = 597  # size of e values of certificates
lh = 256  # domain of the hash function used for the Fiat-Shamir heuristic
lm = 256  # size of attributes
ln = 1024  # size of the RSA modulus
lv = 1700
lo = 80  # security parameter of the SZKP
l = 16  # number of attributes
secparam = 160  # security parameter


# classes

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

    def genKeyPair(self):

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

    def setKeyPair(self, n_pk_i, n_sk_i):

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

    def roundNumber0(self):
        n1 = integer(randomBits(lo))

        return n1

    def roundNumber1(self, p1, n1):

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
        s2.update(Conversion.IP2OS(n1))

        cHat = integer(s2.digest())

        return c == cHat

    def roundNumber1IRMA(self, p1, n1):

        df02_commit = CM_DF02()
        pk_commit = {'S': self.pk_i['S'], 'Z': self.pk_i['Ro'], 'N': self.pk_i['N']}

        sHat = p1['sHat']
        vPrimeHat = p1['vPrimeHat']
        (cA, vPrimeHat) = df02_commit.commit(pk_commit, sHat, 0, vPrimeHat)

        U = p1['U'] % self.pk_i['N']
        c = p1['c']

        Uhat = cA * (U ** (-1 * c))

        list_ints = []
        list_ints.append(int(self.context))
        list_ints.append(int(U))
        list_ints.append(int(Uhat))
        list_ints.append(int(n1))

        ber_context = univ.Integer(list_ints[0])
        ber_pAprime = univ.Integer(list_ints[1])
        ber_That = univ.Integer(list_ints[2])
        ber_n3 = univ.Integer(list_ints[3])

        # ints

        subheader = "0201" + "{:02x}".format(len(list_ints))

        asn1_rep = subheader + ber_encoder.encode(ber_context).encode('hex') + \
                   ber_encoder.encode(ber_pAprime).encode('hex') + \
                   ber_encoder.encode(ber_That).encode('hex') + \
                   ber_encoder.encode(ber_n3).encode('hex')

        # header

        asn1_rep_h = asn1_rep.decode("hex")

        m_len = len(asn1_rep_h)

        i = 0

        len_code = []

        if (m_len <= 0x7f):
            len_code[i] = hex(m_len)
        else:
            j = 0x80;

            while (0 < m_len):
                len_code.append("{:02x}".format(m_len & 0xff))
                m_len = m_len >> 8
                j = j + 1

            len_code.append("{:02x}".format(j))

        len_code.reverse()

        header = "30" + "".join(len_code)  # 0x30, SEQ

        asn1_rep = header + asn1_rep

        s6 = hashlib.new('sha256')
        s6.update(asn1_rep.decode("hex"))

        pChat2 = integer(s6.digest())

        return c == pChat2

    def roundNumber2(self, U, attr, n2):

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

        return (signature, P2)

    def roundNumber2IRMA(self, U, attr, n2):

        offset = integer(1 << (le - 1))

        while True:
            e = randomBits(lePrime - 1)
            e = e + offset

            if isPrime(e):
                break

        vTilde = integer(randomBits(lv - 1))

        vPrimePrime = (2 ** (lv - 1)) + vTilde

        sigA = self.signAttributesLong(attr, vPrimePrime, U, e)

        A = sigA['A']
        Q = sigA['Q']

        phi_N = (self.sk_i['p'] - 1) * (self.sk_i['q'] - 1)
        e2 = e % phi_N

        r = randomPrime(le)

        Atilde = (Q ** r) % self.pk_i['N']

        list_ints = []
        list_ints.append(int(self.context))
        list_ints.append(int(Q))
        list_ints.append(int(A))
        list_ints.append(int(n2))
        list_ints.append(int(Atilde))

        ber_context = univ.Integer(list_ints[0])
        ber_q = univ.Integer(list_ints[1])
        ber_a = univ.Integer(list_ints[2])
        ber_n2 = univ.Integer(list_ints[3])
        ber_atilde = univ.Integer(list_ints[4])

        # ints

        subheader = "0201" + "{:02x}".format(len(list_ints))

        asn1_rep = subheader + ber_encoder.encode(ber_context).encode('hex') + \
                   ber_encoder.encode(ber_q).encode('hex') + \
                   ber_encoder.encode(ber_a).encode('hex') + \
                   ber_encoder.encode(ber_n2).encode('hex') + \
                   ber_encoder.encode(ber_atilde).encode('hex')

        # header

        asn1_rep_h = asn1_rep.decode("hex")

        m_len = len(asn1_rep_h)

        i = 0

        len_code = []

        if (m_len <= 0x7f):
            len_code[i] = hex(m_len)
        else:
            j = 0x80;

            while (0 < m_len):
                len_code.append("{:02x}".format(m_len & 0xff))
                m_len = m_len >> 8
                j = j + 1

            len_code.append("{:02x}".format(j))

        len_code.reverse()

        header = "30" + "".join(len_code)  # 0x30, SEQ

        asn1_rep = header + asn1_rep

        s6 = hashlib.new('sha256')
        s6.update(asn1_rep.decode("hex"))

        cPrimeHex = s6.hexdigest()
        cPrime = integer(s6.digest())

        e2Prime = e2 ** - 1

        pPrimeQprime = ((self.sk_i['p'] - 1) / 2) * ((self.sk_i['q'] - 1) / 2)

        Se = (r - (cPrime * integer(e2Prime))) % pPrimeQprime

        signature = {'A': A, 'e': e, 'vPrimePrime': vPrimePrime}
        P2 = {'Se': Se, 'cPrime': cPrimeHex}

        return (signature, P2)


class Recipient:
    'Idemix Recipient'

    def __init__(self, pk_i, context):
        self.m = {}
        self.pk_i = pk_i
        self.context = context

    def genMasterSecret(self):
        self.ms = integer(randomBits(lm))

    def genRandomAttributes(self, l):
        for i in range(1, l + 1):
            self.m[str(i)] = integer(randomBits(lm))

        Ak = 1 % self.pk_i['N']
        R = self.pk_i['R']

        for i in range(1, len(self.m) + 1):
            Ak = Ak * (R[str(i)] ** self.m[str(i)])

        Ro = self.pk_i['Ro']

        All = Ak * (Ro ** self.ms)

        self.all = All
        self.ak = Ak

        return self.m

    def roundNumber1(self, n1):

        Ro = self.pk_i['Ro']

        df02_commit = CM_DF02()
        pk_commit = {'S': self.pk_i['S'], 'Z': Ro, 'N': self.pk_i['N']}
        (U, self.vPrime) = df02_commit.commit(pk_commit, self.ms, (ln + lo))

        mTilde = integer(randomBits(lm + lo + lh + 1))
        (Utilde, vPrimeTilde) = df02_commit.commit(pk_commit, mTilde, (lm + lo + lh + 1))

        s1 = hashlib.new('sha256')

        s1.update(Conversion.IP2OS(self.context))
        s1.update(Conversion.IP2OS(U))
        s1.update(Conversion.IP2OS(Utilde))
        s1.update(Conversion.IP2OS(n1))

        c = integer(s1.digest())

        # Responses to challenge

        vPrimeHat = vPrimeTilde + (c * self.vPrime)
        sHat = mTilde + (c * self.ms)

        p1 = {'c': c, 'vPrimeHat': vPrimeHat, 'sHat': sHat, 'U': U}
        n2 = integer(randomBits(lo))

        return (p1, n2)

    def roundNumber3(self, signature, P2, n2):

        vPrimePrime = signature['vPrimePrime']

        A = signature['A']
        e = signature['e']

        v = vPrimePrime + self.vPrime

        cPrime = P2['cPrime']
        Se = P2['Se']

        Q2 = (self.pk_i['Z'] / ((self.pk_i['S'] ** v) * self.all)) % self.pk_i['N']

        tmp_u = (self.pk_i['S'] ** self.vPrime) * (self.pk_i['Ro'] ** self.ms) % self.pk_i['N']

        Q22 = (self.pk_i['Z'] / ((self.pk_i['S'] ** vPrimePrime) * self.ak * tmp_u)) % self.pk_i['N']

        Qhat = (A ** e) % self.pk_i['N']
        q2Check = Q2 == Qhat

        Ahat = A ** (cPrime + (Se * e)) % self.pk_i['N']

        s4 = hashlib.new('sha256')

        s4.update(Conversion.IP2OS(self.context))
        s4.update(Conversion.IP2OS(Q2))
        s4.update(Conversion.IP2OS(A))
        s4.update(Conversion.IP2OS(n2))
        s4.update(Conversion.IP2OS(Ahat))

        cHat2 = integer(s4.digest())
        c2Check = cHat2 == cPrime

        sig = {'A': A, 'e': e, 'v': v}

        return (sig, q2Check, c2Check)


class Verifier:
    'Idemix Verifier'

    def __init__(self, pk_i, context):
        self.m = {}
        self.pk_i = pk_i
        self.context = context

    def verifyAllIRMA_NYM_ONLY(self, m, input):
        pAprime = input['pAprime']
        pChat = input['pChat']
        pEhat = input['pEhat']
        mHatMs = input['mHatMs']
        pVprimeHat = input['pVprimeHat']
        n3 = input['n3']
        NYM1 = input['NYM1']
        NYM2 = input['NYM2']

        Ak = 1 % self.pk_i['N']
        R = self.pk_i['R']

        for i in range(1, len(m) + 1):
            Ak = Ak * (R[str(i)] ** m[str(i)])

        That1 = (self.pk_i['Z'] / (Ak * (pAprime ** (2 ** (le - 1))))) ** ((-1 * pChat)) % self.pk_i['N']
        That2 = (pAprime ** pEhat) * (self.pk_i['Ro'] ** mHatMs) * (self.pk_i['S'] ** pVprimeHat) % self.pk_i['N']

        That = (That1 * That2) % self.pk_i['N']

        ## challenge

        s6 = hashlib.new('sha256')

        s6.update(Conversion.IP2OS(NYM2))
        s6.update(Conversion.IP2OS(NYM1))
        s6.update(Conversion.IP2OS(self.context))
        s6.update(Conversion.IP2OS(pAprime))

        s6.update(Conversion.IP2OS(That))

        pChat2 = integer(s6.digest())

        return pChat == pChat2

    def verifyAllIRMA_NYM_H_ONLY(self, m, input):
        pAprime = input['pAprime']
        pChat = input['pChat']
        pEhat = input['pEhat']
        mHatMs = input['mHatMs']
        pVprimeHat = input['pVprimeHat']
        n3 = input['n3']
        NYM1 = input['NYM1']
        NYM2 = input['NYM2']

        mHat1 = m['1'] % self.pk_i['N']

        Ak = 1 % self.pk_i['N']
        R = self.pk_i['R']

        Ak = Ak * (R['1'] ** mHat1)

        That1 = (self.pk_i['Z'] / (Ak * (pAprime ** (2 ** (le - 1))))) ** ((-1 * pChat)) % self.pk_i['N']
        That2 = (pAprime ** pEhat) * (self.pk_i['Ro'] ** mHatMs) * (R['2'] ** m['2']) * (R['3'] ** m['3']) * (
        R['4'] ** m['4']) * (R['5'] ** m['5']) * (self.pk_i['S'] ** pVprimeHat) % self.pk_i['N']

        ThatCred1 = (That1 * That2) % self.pk_i['N']

        ## challenge

        s6 = hashlib.new('sha256')

        s6.update(Conversion.IP2OS(NYM2))
        s6.update(Conversion.IP2OS(NYM1))
        s6.update(Conversion.IP2OS(self.context))
        s6.update(Conversion.IP2OS(pAprime))

        s6.update(Conversion.IP2OS(ThatCred1))

        pChat2 = integer(s6.digest())

        return pChat == pChat2


def SHA1(bytes1):
    s1 = hashlib.new('sha1')
    s1.update(bytes1)
    return s1.digest()


def randomQR(n):
    return random(n) ** 2


context = integer(randomBits(lm))
