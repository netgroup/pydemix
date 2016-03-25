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

from charm.core.math.integer import integer, randomBits

from idemix.settings import *


class CLProver:
    def __init__(self):
        self.e_tilde = None
        self.e_prime = None
        self.v_prime_tilde = None
        self.v_prime = None

    def prove(self, pk_i, credential, cl_predicate, m, m_tilde, ms=None, c=None):
        if not c:
            r_a = integer(randomBits(ln + lo))
            A_prime = (credential['signature']['A'] * (pk_i['S'] ** r_a)) % pk_i['N']
            v_prime = credential['signature']['v'] - (credential['signature']['e'] * r_a)
            e_prime = credential['signature']['e'] - (2 ** (le - 1))

            e_tilde = integer(randomBits(lePrime + lo + lh))
            v_prime_tilde = integer(randomBits(lv + lo + lh))

            R_tot = 1 % pk_i['N']
            for id in credential['attributes']:
                if id not in cl_predicate:
                    R_tot = R_tot * (pk_i['R'][id] ** m_tilde[id])
            R_tot = R_tot * (pk_i['Ro'] ** m_tilde['0'])

            Z_tilde1 = A_prime ** e_tilde
            Z_tilde3 = pk_i['S'] ** v_prime_tilde

            Z_tilde = (Z_tilde1 * R_tot * Z_tilde3) % pk_i['N']

            self.e_tilde = e_tilde
            self.e_prime = e_prime
            self.v_prime_tilde = v_prime_tilde
            self.v_prime = v_prime

            return Z_tilde, A_prime

        else:
            e_hat = self.e_tilde + (c * self.e_prime)
            v_prime_hat = self.v_prime_tilde + (c * self.v_prime)

            m_hat = {}
            for id in credential['attributes']:  # TODO: not in Ar (not revealed!)
                if id not in cl_predicate:
                    m_hat[id] = m_tilde[id] + (c * m[id])
            m_hat['0'] = m_tilde['0'] + (c * ms)

            return {'e_hat': e_hat, 'v_prime_hat': v_prime_hat, 'm_hat': m_hat}



            # def __prove_cg_and(self, predicate, c, m_hat):
            #     m_hat = m_hat[predicate['index']]  # TODO: ?????
            #     m = self.m[str(predicate['index'])]  # TODO: ?????
            #
            #     mr = reduce(mul, c, 1)
            #     r = integer(randomBits(ln))
            #     C = (self.pk_i['Z'] ** m * self.pk_i['S'] ** r) % self.pk_i['N']
            #
            #     lmr = mr.bit_length()
            #     m_h_hat = integer(randomBits(lm + lo + lh + 1 - lmr))
            #     r_hat = integer(randomBits(ln + lo + lh + 1))
            #
            #     C_hat = ((self.pk_i['Z'] ** mr) ** m_h_hat * self.pk_i['S'] ** r_hat) % self.pk_i['N']
            #     C0_hat = (self.pk_i['Z'] ** m_hat * self.pk_i['S'] ** r_hat) % self.pk_i['N']
            #
            #     return {'t-value': {'C_hat': C_hat, 'C0_hat': C0_hat}, 'common-value': C}
            #
            # def __prove_cg_not(self, predicate, c, m_hat):
            #     m = self.m[str(predicate['index'])]  # TODO: ?????
            #
            #     mr = reduce(mul, c, 1)
            #
            #     r = integer(randomBits(ln))
            #     C = (self.pk_i['Z'] ** m * self.pk_i['S'] ** r) % self.pk_i['N']
            #
            #     r_hat = integer(randomBits(ln + lo + lh + 1))
            #     m_hat = integer(randomBits(ln + lo + lh + 1))
            #
            #     a, b = egcd(m, mr)  # m * a + mr * b = 1
            #     r_prime = -r * a
            #
            #     ni = 1  # TODO:????
            #     lt = 1  # TODO:????
            #     r_prime_hat = integer(randomBits(lm + lo + lh + 1 - (ni * lt)))
            #     a_hat = integer(randomBits(lm + lo + lh + 1 - (ni * lt)))
            #     b_hat = integer(randomBits(lm + lo + lh + 1 - (ni * lt)))
            #
            #     C_hat = (C ** a_hat * (self.pk_i['Z'] ** mr) ** b_hat * self.pk_i['S'] ** r_prime_hat) % self.pk_i['N']
            #
            #     return {'t-value': {'C_hat': C_hat}, 'common-value': C}
