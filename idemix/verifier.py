'''
:Authors:    Alberto Caponi, Claudio Pisa
:Date:       02/2016
 '''
import hashlib

from charm.core.math.integer import integer, random, randomBits
from charm.toolbox.conversion import Conversion

from idemix.settings import le, lo


class Verifier:
    'Idemix Verifier'

    def __init__(self, pk_i, context):
        self.m = {}
        self.t_values = []
        self.pk_i = pk_i
        self.context = context

    def get_nonce(self):
        nv = integer(randomBits(lo))

        return nv

    def verifyProof(self, credential, predicate, P, nv):
        T_hat = {}
        T_hat['t-values'] = self.__verify_cl(credential, predicate, P)

        # print "That:", T_hat['t-values']

        h_challenge = hashlib.new('sha256')
        h_challenge.update(Conversion.IP2OS(self.context))
        h_challenge = self.__add_dict_to_hash(P['common'], h_challenge)
        h_challenge = self.__add_dict_to_hash(T_hat, h_challenge)  # TODO: ricontrollare!
        h_challenge = self.__add_list_to_hash([], h_challenge)  # committed, representation, nym, dnym, verenc, msg
        h_challenge.update(Conversion.IP2OS(nv))
        c = integer(h_challenge.digest())

        return c == P['c']

    def __verify_cl(self, credential, predicate, P):

        A_prime = P['common']['A_prime']
        m = credential['attributes']
        m_hat = P['s']['m_hat']
        e_hat = P['s']['e_hat']
        v_prime_hat = P['s']['v_prime_hat']
        c = P['c']

        Rtot = 1 % self.pk_i['N']
        Rtot_hat = 1 % self.pk_i['N']

        for id in predicate:
            Rtot = Rtot * (self.pk_i['R'][id] ** m[id])

        for id, v in m_hat.iteritems():
            if id is not '0':
                Rtot_hat = Rtot_hat * (self.pk_i['R'][id] ** m_hat[id])
        Rtot_hat = Rtot_hat * (self.pk_i['Ro'] ** m_hat['0'])

        den = Rtot * (A_prime ** (2 ** (le - 1)))
        T_hat_1 = (self.pk_i['Z'] / den) ** (-1 * c)
        T_hat_2 = A_prime ** e_hat
        T_hat_3 = self.pk_i['S'] ** v_prime_hat

        T_hat = (T_hat_1 * T_hat_2 * Rtot_hat * T_hat_3) % self.pk_i['N']

        # TODO: check lengths

        return T_hat

    def __add_list_to_hash(self, list_obj, hash_obj):
        for e in list_obj:
            hash_obj.update(Conversion.IP2OS(e))
        return hash_obj

    def __add_dict_to_hash(self, dict_obj, hash_obj):
        for k, v in dict_obj.iteritems():
            hash_obj.update(Conversion.IP2OS(v))

        return hash_obj

        # def verifyAllIRMA_NYM_ONLY(self, m, input):
        #     pAprime = input['pAprime']
        #     pChat = input['pChat']
        #     pEhat = input['pEhat']
        #     mHatMs = input['mHatMs']
        #     pVprimeHat = input['pVprimeHat']
        #     n3 = input['n3']
        #     NYM1 = input['NYM1']
        #     NYM2 = input['NYM2']
        #
        #     Ak = 1 % self.pk_i['N']
        #     R = self.pk_i['R']
        #
        #     for i in range(1, len(m) + 1):
        #         Ak = Ak * (R[str(i)] ** m[str(i)])
        #
        #     That1 = (self.pk_i['Z'] / (Ak * (pAprime ** (2 ** (le - 1))))) ** ((-1 * pChat)) % self.pk_i['N']
        #     That2 = (pAprime ** pEhat) * (self.pk_i['Ro'] ** mHatMs) * (self.pk_i['S'] ** pVprimeHat) % self.pk_i['N']
        #
        #     That = (That1 * That2) % self.pk_i['N']
        #
        #     ## challenge
        #
        #     s6 = hashlib.new('sha256')
        #
        #     s6.update(Conversion.IP2OS(NYM2))
        #     s6.update(Conversion.IP2OS(NYM1))
        #     s6.update(Conversion.IP2OS(self.context))
        #     s6.update(Conversion.IP2OS(pAprime))
        #
        #     s6.update(Conversion.IP2OS(That))
        #
        #     pChat2 = integer(s6.digest())
        #
        #     return pChat == pChat2
        #
        # def verifyAllIRMA_NYM_H_ONLY(self, m, input):
        #     pAprime = input['pAprime']
        #     pChat = input['pChat']
        #     pEhat = input['pEhat']
        #     mHatMs = input['mHatMs']
        #     pVprimeHat = input['pVprimeHat']
        #     n3 = input['n3']
        #     NYM1 = input['NYM1']
        #     NYM2 = input['NYM2']
        #
        #     mHat1 = m['1'] % self.pk_i['N']
        #
        #     Ak = 1 % self.pk_i['N']
        #     R = self.pk_i['R']
        #
        #     Ak = Ak * (R['1'] ** mHat1)
        #
        #     That1 = (self.pk_i['Z'] / (Ak * (pAprime ** (2 ** (le - 1))))) ** ((-1 * pChat)) % self.pk_i['N']
        #     That2 = (pAprime ** pEhat) * (self.pk_i['Ro'] ** mHatMs) * (R['2'] ** m['2']) * (R['3'] ** m['3']) * (
        #         R['4'] ** m['4']) * (R['5'] ** m['5']) * (self.pk_i['S'] ** pVprimeHat) % self.pk_i['N']
        #
        #     ThatCred1 = (That1 * That2) % self.pk_i['N']
        #
        #     ## challenge
        #
        #     s6 = hashlib.new('sha256')
        #
        #     s6.update(Conversion.IP2OS(NYM2))
        #     s6.update(Conversion.IP2OS(NYM1))
        #     s6.update(Conversion.IP2OS(self.context))
        #     s6.update(Conversion.IP2OS(pAprime))
        #
        #     s6.update(Conversion.IP2OS(ThatCred1))
        #
        #     pChat2 = integer(s6.digest())
        #
        #     return pChat == pChat2


def SHA1(bytes1):
    s1 = hashlib.new('sha1')
    s1.update(bytes1)
    return s1.digest()


def randomQR(n):
    return random(n) ** 2
