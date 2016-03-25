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

from idemix.issuer import Issuer
from idemix.recipient import Recipient
from idemix.settings import lm, l, secparam
from idemix.verifier import Verifier

context = integer(randomBits(lm))

attr = {'1': 'student', '2': 'italian', '3': 'age'}
for id, value in attr.iteritems():
    h_challenge = hashlib.new('sha256')
    h_challenge.update(str(value))
    attr[id] = Conversion.bytes2integer(h_challenge.digest())

issuer = Issuer(len(attr), 0, 0, secparam, context)
pk_i, sk_i = issuer.gen_key_pair()
# print sk_i
assert issuer.selfTest()

user = Recipient(pk_i, context)
user.gen_master_secret()
user.set_attributes(attr)
# attr = user.gen_random_attributes(l)


# ISSUING PROTOCOL
n1 = issuer.round_0()  # Generate nonce
p1, n2 = user.round_1(n1)
signature, P2 = issuer.round_2(p1['U'], p1, attr, n2)
sig, q2Check, c2Check = user.round_3(signature, P2, n2)

# print "Nonce 1", n1
# print "P1", p1
# print "Nonce 2", n2
# print "Signature", signature
# print "P2", P2
print "Sig", sig
print q2Check
print c2Check

credential = {'attributes': attr, 'signature': sig}
predicate = []#attr.keys()

verifier = Verifier(pk_i, context)
nv = verifier.get_nonce()

# VERIFYING PROTOCOL
proof = user.build_proof(credential, predicate, nv)

print proof
a = {}
for id, value in credential["attributes"].iteritems():
    if id in predicate:
        a[id] = value

proof_credential = {'attributes': a}

print "Credential sent to verifier:", proof_credential
# print proof
witness = verifier.verifyProof(credential, predicate, proof, nv)

if witness:
    print "Proof verified"
else:
    print "Proof not valid"
