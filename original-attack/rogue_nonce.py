#!/usr/bin/env sage

from sage.all import GF, PolynomialRing, matrix
import hashlib
import ecdsa
import random

def separator():
	print("-" * 150)


#####################
# global parameters #
#####################

# choose any curve
usedcurve = ecdsa.curves.SECP256k1
# usedcurve = ecdsa.curves.NIST521p
# usedcurve = ecdsa.curves.BRAINPOOLP160r1

print("Selected curve :")
print(usedcurve.name)
separator()

# the private key that will be guessed
g = usedcurve.generator
d = random.randint(1, usedcurve.order - 1)
pubkey = ecdsa.ecdsa.Public_key( g, g * d )
privkey = ecdsa.ecdsa.Private_key( pubkey, d )
print("Private key :")
print(d)
separator()

# N = the number of signatures to use, N >= 4
# the degree of the recurrence relation is N-3
# the number of unknown coefficients in the recurrence equation is N-2
# the degree of the final polynomial in d is 1 + Sum_(i=1)^(i=N-3)i

N = 8
assert N >= 4

# declaring stuff for manipulating polynomials with SAGE
Z = GF(usedcurve.order)
R = PolynomialRing(Z, names=('dd',))
(dd,) = R._first_ngens(1)


############################################################
# nonces and signature generation with recurrence relation #
############################################################

# ok, this is the "rogue nonce" version of the approach
# the key finding part is the same, the difference is in the way signatures are generated
# instead of fixing a recurrence relation and generating the nonces this way, we generate N-1 nonces randomly, and choose the Nth one so that it follows the recurrence relation
# the coefficients of the recurrence relation are given by the first N-1 nonces in the given order
# basically, it's like we take N-1 arbitrary signatures from a given private key, and we generate one more "redundant" nonce

# first, we randomly generate N-1 nonces
k = []
for i in range(N-1):
	k.append(random.randint(1, usedcurve.order - 1))

# then, we find the recurrence coefficients that would give this series of nonces
# we use sage to create a matrix and invert it
mrows = []
for i in range(N-2):
	current_row = []
	for j in range(N-2):
		current_row.append(pow(k[i], N-3-j, usedcurve.order))
	mrows.append(current_row)
km = matrix(Z, mrows)
kvec = []
for i in range(1, N-1):
	kvec.append(k[i])
kv = matrix(Z, N-2, 1, kvec)
kminv = km.inverse_of_unit()
avec = kminv * kv

# compute and append the rogue nonce
rogue_nonce = Z(0)
for i in range(N-2):
	rogue_nonce = rogue_nonce + avec[i][0]*pow(k[N-2], N-3-i, usedcurve.order)
rogue_nonce_sageint = rogue_nonce.lift()
rogue_nonce_str = rogue_nonce_sageint.str()
rogue_nonce_int = int(rogue_nonce_str)
k.append(rogue_nonce_int)


# then, we generate the signatures using the nonces
h = []
sgns = []
for i in range(N):
	digest_fnc = hashlib.new("sha256")
	digest_fnc.update(b"recurrence test ")
	digest_fnc.update(i.to_bytes(1, 'big'))
	h.append(digest_fnc.digest())
	# get hash values as integers and comply with ECDSA
	# strangely, it seems that the ecdsa module does not take the leftmost bits of hash if hash size is bigger than curve... perahps is because i use low level functions
	if usedcurve.order.bit_length() < 256:
		h[i] = (int.from_bytes(h[i], "big") >> (256 - usedcurve.order.bit_length())) % usedcurve.order
	else:
		h[i] = int.from_bytes(h[i], "big") % usedcurve.order
	sgns.append(privkey.sign( h[i], k[i] ))


# get signature parameters as arrays
s_inv = []
s = []
r = []
for i in range(N):
	s.append(sgns[i].s)
	r.append(sgns[i].r)
	s_inv.append(ecdsa.numbertheory.inverse_mod(s[i], usedcurve.order))


#########################################
# generating the private-key polynomial #
#########################################


# the polynomial we construct will have degree 1 + Sum_(i=1)^(i=N-3)i in dd
# our task here is to compute this polynomial in a constructive way starting from the N signatures in the given list order
# the generic formula will be given in terms of differences of nonces, i.e. k_ij = k_i - k_j where i and j are the signature indexes
# each k_ij is a first-degree polynomial in dd
# this function has the goal of returning it given i and j
def k_ij_poly(i, j):
	hi = Z(h[i])
	hj = Z(h[j])
	s_invi = Z(s_inv[i])
	s_invj = Z(s_inv[j])
	ri = Z(r[i])
	rj = Z(r[j])
	poly = dd*(ri*s_invi - rj*s_invj) + hi*s_invi - hj*s_invj
	return poly

# the idea is to compute the polynomial recursively from the given degree down to 0
# the algorithm is as follows:
# for 4 signatures the second degree polynomial is:
# k_12*k_12 - k_23*k_01
# so we can compute its coefficients.
# the polynomial for N signatures has degree 1 + Sum_(i=1)^(i=N-3)i and can be derived from the one for N-1 signatures

# let's define dpoly(i, j) recursively as the dpoly of degree i starting with index j


def dpoly(n, i, j):
	if i == 0:
		return (k_ij_poly(j+1, j+2))*(k_ij_poly(j+1, j+2)) - (k_ij_poly(j+2, j+3))*(k_ij_poly(j+0, j+1))
	else:
		left = dpoly(n, i-1, j)
		for m in range(1,i+2):
			left = left*(k_ij_poly(j+m, j+i+2))
		right = dpoly(n, i-1, j+1)
		for m in range(1,i+2):
			right = right*(k_ij_poly(j, j+m))
		return (left - right)


def print_dpoly(n, i, j):
	if i == 0:
		print('(k', j+1, j+2, '*k', j+1, j+2, '-k', j+2, j+3, '*k', j+0, j+1, ')', sep='', end='')
	else:
		print('(', sep='', end='')
		print_dpoly(n, i-1, j)
		for m in range(1,i+2):
			print('*k', j+m, j+i+2, sep='', end='')
		print('-', sep='', end='')
		print_dpoly(n, i-1, j+1)
		for m in range(1,i+2):
			print('*k', j, j+m, sep='', end='')
		print(')', sep='', end='')


print("Nonces difference equation :")
print_dpoly(N-4, N-4, 0)
print(' = 0', sep='', end='')
print()
separator()

poly_target = dpoly(N-4, N-4, 0)
print("Polynomial in d :")
print(poly_target)
separator()

d_guesses = poly_target.roots()
print("Roots of the polynomial :")
print(d_guesses)
separator()

# check if the private key is among the roots
for i in d_guesses:
	if i[0] == d:
		print("key found!!!")
