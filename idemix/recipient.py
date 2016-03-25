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

from charm.core.math.integer import integer, randomBits
from charm.toolbox.conversion import Conversion

from idemix.provers.cl_prover import CLProver
from idemix.settings import *
from idemix.utils.commit_df02 import CM_DF02


def egcd(a, b):
    pass


class Recipient:
    'Idemix Recipient'

    def __init__(self, pk_i, context):
        self.m = {}
        self.v_tilde = {}
        self.t_values = {}
        self.common_value = {}
        self.pk_i = pk_i
        self.context = context

    def gen_master_secret(self):
        self.ms = integer(randomBits(lm))

    def gen_random_attributes(self, l):
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

    def set_attributes(self, attr):
        Ak = 1 % self.pk_i['N']
        R = self.pk_i['R']

        self.m = attr

        for i in range(1, len(attr) + 1):
            Ak = Ak * (R[str(i)] ** self.m[str(i)])

        Ro = self.pk_i['Ro']

        All = Ak * (Ro ** self.ms)

        self.all = All
        self.ak = Ak

        return self.m

    def round_1(self, n1):

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

        return p1, n2

    def round_3(self, signature, P2, n2):

        vPrimePrime = signature['vPrimePrime']

        A = signature['A']
        e = signature['e']

        v = vPrimePrime + self.vPrime

        cPrime = P2['cPrime']
        Se = P2['Se']

        Q2 = (self.pk_i['Z'] / ((self.pk_i['S'] ** v) * self.all)) % self.pk_i['N']

        # tmp_u = (self.pk_i['S'] ** self.vPrime) * (self.pk_i['Ro'] ** self.ms) % self.pk_i['N']

        # Q22 = (self.pk_i['Z'] / ((self.pk_i['S'] ** vPrimePrime) * self.ak * tmp_u)) % self.pk_i['N']

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

        return sig, q2Check, c2Check

    def build_proof(self, credentials, predicate, n1):
        # step 0.1
        for key, value in self.m.iteritems():
            self.v_tilde[key] = integer(randomBits(lm + lo + lh))
            # print self.v_hat
        self.v_tilde['0'] = integer(randomBits(lm + lo + lh))
        cl_prover = CLProver()
        # print self.all
        # step 1.1: t-values
        t_value, common_value = cl_prover.prove(self.pk_i, credentials, predicate, self.m, self.v_tilde)

        self.t_values['Z_tilde'] = t_value
        self.common_value['A_prime'] = common_value

        # step 2.1: challenge
        h_challenge = hashlib.new('sha256')
        h_challenge.update(Conversion.IP2OS(self.context))
        h_challenge = self.__add_dict_to_hash(self.common_value, h_challenge)
        h_challenge = self.__add_dict_to_hash(self.t_values, h_challenge)
        h_challenge = self.__add_list_to_hash([], h_challenge)  # committed, representation, nym, dnym, verenc, msg
        h_challenge.update(Conversion.IP2OS(n1))
        c = integer(h_challenge.digest())

        # print "t-value:", t_value

        # step 3.1: s-values
        s_values = cl_prover.prove(self.pk_i, credentials, predicate, self.m, self.v_tilde, self.ms, c)

        # step 4.1: return proof
        proof = {}
        proof['c'] = c
        proof['s'] = s_values
        proof['common'] = self.common_value
        return proof

    def __add_list_to_hash(self, list_obj, hash_obj):
        for e in list_obj:
            hash_obj.update(Conversion.IP2OS(e))
        return hash_obj

    def __add_dict_to_hash(self, dict_obj, hash_obj):
        for k, v in dict_obj.iteritems():
            hash_obj.update(Conversion.IP2OS(v))

        return hash_obj
