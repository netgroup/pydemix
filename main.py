import hashlib

from charm.core.math.integer import integer, randomBits
from charm.toolbox.conversion import Conversion

from idemix.issuer import Issuer
from idemix.recipient import Recipient
from idemix.settings import lm, l, secparam
from idemix.verifier import Verifier

context = integer(randomBits(lm))

attr = {'1': 'alberto', '2': 'caponi', '3': 29}
for id, value in attr.iteritems():
    h_challenge = hashlib.new('sha256')
    h_challenge.update(str(value))
    attr[id] = Conversion.bytes2integer(h_challenge.digest())

issuer = Issuer(len(attr), 0, 0, secparam, context)
pk_i, sk_i = issuer.gen_key_pair()
# print pk_i
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
# print "Sig", sig

credential = {'attributes': attr, 'signature': sig}
predicate = []#attr.keys()

verifier = Verifier(pk_i, context)
nv = verifier.get_nonce()

# VERIFYING PROTOCOL
proof = user.build_proof(credential, predicate, nv)

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
