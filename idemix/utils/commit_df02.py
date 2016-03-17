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
Damgard-Fujisaki-Okamoto Commitment Scheme
 
| From: "I. Damgard, E. Fujisaki. An integer commitment scheme based on groups with 
|         hidden order".
| Published in: ASIACRYPT 2002
| Available from: https://eprint.iacr.org/2001/064.ps
| Notes: The setup functions are based on the Idemix issuing operation. 
| 	See https://prime.inf.tu-dresden.de/idemix/ (page 15).

* type:		commitment
* setting:	integer groups

:Authors:	Antonio de la Piedra
:Date:		12/2013
'''

import hashlib

from charm.core.math.integer import integer, random, randomBits
from charm.toolbox.Commit import Commitment


def SHA1(bytes1):
    s1 = hashlib.new('sha1')
    s1.update(bytes1)
    return s1.digest()


def randomQR(n):
    return random(n) ** 2


debug = False


class CM_DF02(Commitment):
    """
    >>> from charm.toolbox.conversion import Conversion
    >>> commitment = CM_DF02()
    >>> p = integer(333437049425486136095925931727629203622119239282802038455917646172563395024265917241890473852501318262109839243221497854682815506880304349748481648877420618747530394310060738051284980323398797638078562462943477904211178707988798971266777314022673227003284335883622084916018185539789562312940907090712386355299)
    >>> q = integer(294092988306368388636535355362351220952777074915662080329740789451817968606482246364359892865057621298389179478994706465098262699509935804409002480293234947971872131356003427444279672200378079370695651721652248116723483318427208508192689675310517884904089979454005634358395042846262967137935407297336359215239)
    >>> N = p*q
    >>> pk = commitment.setup(N=N)
    >>> msg = integer(SHA1(Conversion.IP2OS(random(pk['N']))))
    >>> lr = 2048 + 80
    >>> (c, d) = commitment.commit(pk, msg, lr)
    >>> commitment.decommit(pk, c, d, msg)
    True
    >>> pk = commitment.setupBlock(N=N, l=16)
    >>> msg = {}
    >>> l = 16
    >>> for i in range(1, l + 1): msg[str(i)] = integer(SHA1(Conversion.IP2OS(random(pk['N']))))
    >>> lr = 2048 + 80
    >>> (c, d) = commitment.commitBlock(pk, msg, lr)
    >>> commitment.decommitBlock(pk, c, d, msg)
    True
    """

    def __init__(self):
        Commitment.__init__(self)

    def setup(self, secparam=None, N=0):
        Xz = integer(random(N))

        S = randomQR(N)
        Z = S ** Xz

        return {'S': S, 'Z': Z, 'N': N}

    def setupBlock(self, secparam=None, N=0, l=16):
        Xr = {}

        for i in range(1, l + 1):
            Xr[str(i)] = integer(random(N))

        S = randomQR(N)
        R = {}

        for i in range(1, l + 1):
            R[str(i)] = S ** Xr[str(i)]

        return {'S': S, 'R': R, 'N': N}

    def commit(self, pk, msg, lr, ri=0):
        S = pk['S']
        Z = pk['Z']

        if (lr == 0):
            r = ri
        else:
            r = integer(randomBits(lr))

        c = ((Z ** msg) * (S ** r)) % pk['N']
        d = r

        return (c, d)

    def commitBlock(self, pk, msg, lr, ri=0):
        Cx = 1 % pk['N']

        R = pk['R']
        S = pk['S']

        if (lr == 0):
            r = ri
        else:
            r = integer(randomBits(lr))

        for i in range(1, len(msg) + 1):
            Cx = Cx * (R[str(i)] ** msg[str(i)])

        c = (Cx * (S ** r)) % pk['N']
        d = r

        return (c, d)

    def decommit(self, pk, c, d, msg):
        S = pk['S']
        Z = pk['Z']

        cP = ((Z ** msg) * (S ** d)) % pk['N']

        return c == cP

    def decommitBlock(self, pk, c, d, msg):
        Cx = 1 % pk['N']

        R = pk['R']
        S = pk['S']

        for i in range(1, len(msg) + 1):
            Cx = Cx * (R[str(i)] ** msg[str(i)])

        cP = (Cx * (S ** d)) % pk['N']

        return c == cP
