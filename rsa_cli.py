"""
Client for the updated RSA assignment.
In progress.
"""

import rsa
import argparse
import sys
import hashlib
import pickle
import math

# Setting up argparse to deal with commandline arguments 

parser = argparse.ArgumentParser(description='Runs RSA')
parser.add_argument('-e', help='encrypt', action='store_true', default=False)
parser.add_argument('-d', help='decrypt', action='store_true', default=False)
parser.add_argument('-i', help='input file', nargs=1)
parser.add_argument('-o', help ='output file (if not specified, stdout)', nargs=1)
parser.add_argument('-g', help = 'Generate a key of specific size; use with -o for base file name', nargs=1)
parser.add_argument('-k', help = 'key file (required for encrypt, decrypt, sign, and verify)', nargs=1)
parser.add_argument('-s', help = 'sign', action='store_true', default=False)
parser.add_argument('-v', help = 'verify', action='store_true', default=False)

args = parser.parse_args()

# Check that the arguments are properly formatted
def checkIOArgs(i=False, o=False, k=False):
	if i and not args.i:
		raise Exception("Action requires Input File")
	if o and not args.o:
		raise Exception("Action requires Output File")
	if k and not args.k:
		raise Exception("Action requires Key File")

##### Text/File Processing #####

# Function to convert a string into its integer representation
# We need this because RSA only works on integers not strings
def str_to_int(s):
	return int(''.join(("%x" % ord(c)).zfill(2) for c in s), 16)

# Function to convert from a integer back into a string representation
# For displaying our ciphertext or plaintext to users
def int_to_str(i):
	if i < 1:
		return ""
	strlen = int(math.ceil(math.log(i, 256)))
	s = [""] * strlen
	for j in reversed(range(0, strlen)):
		s[j] = chr(i & 0xff)
		i /= 256
	return ''.join(s)

# Function to convert a string found in file f into blocks(strings)
# of length blocklen
# The encyption/decryption algorithm given by argument fn
# is then called upon each block
# This function is necessary because RSA can only encrypt strings
# of length < n
def blockify(blocklen, f, fn, fill='\x00'):
	cont = True
	while cont:
		block = f.read(blocklen)
		if len(block) < blocklen:
			if len(block) == 0:
				break
			cont = False
		# print "block: <%s>" % b
		fn(block.rjust(blocklen, fill))

# Function to convert a string given by argument s 
# into blocks(strings) of length blocklen
# The encyption/decryption algorithm given by argument fn
# is then called upon each block 'b'
def blockifys(blocklen, s, fn, fill='\x00'):
	while len(s) > 0:
		b = s[:blocklen]
		# print "block: <%s>" % b
		fn(b.rjust(blocklen, fill))
		s = s[blocklen:]

# Function to load the information found in a public or private key file
# file -> []
def getKey(kfilename):
	with open(kfilename, "r") as kfile:
		k = pickle.load(kfile)
	return k

# Function to store a key into a public or private key file
# [] -> file
def putKey(k, kfilename):
	with open(kfilename, "w") as kfile:
		pickle.dump(k, kfile)


##### Active Functions #####
# function to take an input file inp and write it's encrypted form to the file outp
# The key to be used is given by the argument key
def do_encrypt(inp, outp, key):
	keylen = math.log(k[0], 2)
	def encrypt_block(m):
		m = str_to_int(m)	# Convert to int
		m = "%x" % rsa.encrypt(m, key) # Encrypt and convert to hex
		m = m.zfill(int(math.ceil(keylen / 4.0)))	# Pad it to the correct length (hex if 4 bits per character)
		outp.write(m)
	blockify(int(keylen) // 8, inp, encrypt_block)

# function to take an input file inp and write it's decrypted form to the file outp
# The key to be used is given by the argument key
def do_decrypt(inp, outp, key):
	keylen = math.log(k[0], 2)
	def decrypt_block(m):
		m = int(m, 16)	# Convert from hex to integer
		m = rsa.decrypt(m, key)	# Decrypt
		m = int_to_str(m)	# Convert to ascii
		outp.write(m)
	blockify(int(math.ceil(keylen / 4.0)), inp, decrypt_block, "0")	# 4 bits per hex digit, padded with 0s

# function to take a file inp and write the signed version of that file to outp
# signing is done with the private key 'key'
def do_sign(inp, outp, key):
	keylen = math.log(k[0], 2)
	h = hashlib.sha256()
	blockify(int(keylen // 2), inp, h.update)   # Get hash for file
	h = h.hexdigest()

	def sign_block(h_block):
		h_block = "%x" % rsa.decrypt(int(h_block, 16), k)
		h_block = h_block.zfill(int(keylen // 4))	# Pad with zeros
		outp.write(h_block)
		print(h_block)
	blockifys(int(keylen // 4), h, sign_block)

	# Write the rest of the file
	outp.write("\n")
	inp.seek(0)
	for line in inp:
		outp.write(line)

# function to take a signed file inp and return if it was signed 
# using the correct key or not, verification is accomplished using
# the public key 'key'
def do_verify(inp, key):
	keylen = math.log(k[0], 2)
	hsigned = inp.readline()[:-1]	# Take off the trailing newline
	h2 = hashlib.sha256()
	blockify(int(keylen // 2), inp, h2.update)  # Get hash for rest of file
	h2 = h2.hexdigest()
	h = [""]
	
	def verify_block(x):
		print(x)
		x = int(x, 16)	# Convert to integer
		x = rsa.encrypt(x, k)	# Decrypt
		h[0] += "%x" % x 	# Append to hash

	blockifys(int(math.ceil(keylen / 4)), hsigned, verify_block)
	# print h[0]
	# print h2
	return h[0] == h2


##### Main Control Flow #####

# Main function, calls other functions depending on the command line
# arguments given by the user
if __name__ == "__main__":
	if args.i:
		inp = open(args.i[0], "r")
	if args.o:
		outp = open(args.o[0], "w")
	else:
		outp = sys.stdout
	if args.k:
		k = getKey(args.k[0])

	if args.e:
		checkIOArgs(i=True, o=True)
		do_encrypt(inp, outp, k)
	elif args.d:
		checkIOArgs(i=True, k=True)
		do_decrypt(inp, outp, k)
	elif args.g:
		checkIOArgs(o=True)
		kpriv, kpub = rsa.key_gen(int(args.g[0]))
		putKey(kpriv, args.o[0])
		putKey(kpub, args.o[0] + ".pub")
	elif args.s:
		checkIOArgs(i=True, o=True, k=True)
		do_sign(inp, outp, k)
	elif args.v:
		checkIOArgs(i=True, k=True)
		if do_verify(inp, k):
			print("Verified")
		else:
			print("Verification failed")