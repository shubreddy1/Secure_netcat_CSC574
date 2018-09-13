import socket
import pickle
import select 
import sys
import bcrypt
import time
import random
import hashlib, binascii
from Crypto.Cipher import AES

MAX_MSG_LEN = 6	#Accepts messages up to 10^(6-1) chars long

#Crypto module for encryption, decryption and salt, nonce and key generation
class snc_crypto_module():

        #Function to generate nonce of a particular length
        def gen_nonce(self, nonce_len):
                curr_nonce = ""
                while len(curr_nonce) < nonce_len:
                        random.seed(time.clock())
                        curr_nonce += str(random.randint(0,1000000))
                return curr_nonce[:nonce_len]

        #Function to generate salt
        def gen_salt(self):
                return bcrypt.gensalt()

        #Function to generate password from pbkd function
        def gen_pbkdf(self, key):
                derived_key = hashlib.pbkdf2_hmac('sha256', key, "SALT", 1000)
                return binascii.hexlify(derived_key)[:16]

        #Function to encrypt a message with a key and nonce using AES gcm
        def encrypt_message(self, message, key, nonce):
                cipher = AES.new(key, AES.MODE_GCM, nonce)
                return cipher.encrypt(message)

        #Function to decrypt a message with a key and nonce using AES gcm
        def decrypt_message(self, message, key, nonce):
                cipher = AES.new(key, AES.MODE_GCM, nonce)
                return cipher.decrypt(message)

        #Pack and serialize message
        def pack_message(self, message, key, nonce):
                enc_message = self.encrypt_message(message, key, nonce)
                hasher = hashlib.sha256()
                hasher.update(enc_message)
		hasher.update(key)
                message_hash = hasher.digest()
                wrapper = message_wrapper(enc_message, nonce, message_hash)
                return pickle.dumps(wrapper)

	#Unpack and deserialize message
	def unpack_message(self, message, key, nonce):
		wrapper = pickle.loads(message)
		hasher = hashlib.sha256()
		hasher.update(wrapper.message)
		hasher.update(key)
		hash_value = hasher.digest()
		#print hash_value, wrapper.message_hash
		if hash_value != wrapper.message_hash:
			return -1
		return self.decrypt_message(wrapper.message, key, wrapper.nonce)

#Socket handler class to manage socket reads and writes
#First sends a 5 char string which denotes the length of message, and then sends the message
class socket_handler():
        def __init__(self, sock):
                self.socket = sock

        def socket_read(self):
		try:
	                message_len = int(self.socket.recv(MAX_MSG_LEN))
	                message_parts = []
	
	                while message_len >= 1024:
	                        message_parts.append(self.socket.recv(1024))
	                        message_len -= 1024
	
	                if message_len > 0:
	                        message_parts.append(self.socket.recv(message_len))
	
	                return "".join(message_parts)

		except Exception as e:
			#print str(e)
			return -1

        def socket_write(self, message):
		try:
	                message_len = len(message)
	                self.socket.send("0"*(MAX_MSG_LEN - len(str(message_len))) + str(message_len))
	
	                start_indx = 0
	                while message_len >= 1024:
	                        self.socket.send(message[start_indx:start_indx+1024])
	                        start_indx += 1024
	                        message_len -= 1024
	
	                if message_len > 0:
	                        self.socket.send(message[start_indx:start_indx+message_len])
	
	                return
		except Exception as e:
			#print str(e)
			return -1

#Message wrapper to store message, nonce and hash of the message
class message_wrapper():
        def __init__(self, message, nonce, message_hash):
                self.message = message
                self.nonce = nonce
                self.message_hash = message_hash


