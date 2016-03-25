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

global lm, ln, lo, lh, le, l, lv, lePrime, secparam

lePrime = 120  # size of the interval the e valus are taken from
le = 597  # size of e values of certificates
lh = 256  # domain of the hash function used for the Fiat-Shamir heuristic
lm = 256  # size of attributes
ln = 1024  # size of the RSA modulus
lv = 1700
lo = 80  # security parameter of the SZKP
l = 3  # number of attributes
secparam = 160  # security parameter
