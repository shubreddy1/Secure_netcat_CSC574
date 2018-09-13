import argparse
import socket
import sys
import select
from snc_lib import snc_crypto_module, socket_handler, message_wrapper

#Argparse to parse the arguments
snc_parser = argparse.ArgumentParser(description='Secure netcat client')

snc_parser.add_argument('--key', metavar='my_secret_key', nargs=1, help="Secret key used to verify the authenticity of server's messages")

snc_parser.add_argument('server_ip', metavar='server_ip_address', nargs=1, help='The ip address of the server' )

snc_parser.add_argument('server_port', metavar='server_port_number', type=int, nargs=1, help='The port number on which the server listens' )

snc_args = snc_parser.parse_args()

secret_key, server_ip, server_port = snc_args.key[0], snc_args.server_ip[0], snc_args.server_port[0]

#Initialize crypto module and generate key, nonce
c_module = snc_crypto_module()
secret_key = c_module.gen_pbkdf(secret_key)
my_nonce = c_module.gen_nonce(32)

#Socket creation
nc_client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#Check for connection errors
try:
	ret_val = nc_client_sock.connect((server_ip, server_port))
except Exception as e:
	print str(e)
	sys.exit(0)

#Handle errors in input and socket
try:
	#Creating the crypto module object and select on stdin & socket
	crypto_mod = snc_crypto_module()
	inputs = [sys.stdin, nc_client_sock]
	outputs = []
	client_handle = socket_handler(nc_client_sock)
	while 1:
		#Select one from inputs which has data buffered
		readable, writable, exceptional = select.select(inputs, outputs, inputs)
		
		for read_obj in readable:

			#If it is stdin, encrypt and send
			if read_obj is sys.stdin:
				ip_line = sys.stdin.readline()
				#If empty data is read EOF was encountered
				if not ip_line:
					sys.exit()
				else:
					client_handle.socket_write(crypto_mod.pack_message(ip_line[:-1], secret_key, my_nonce))

			#Else input from socket has to be processed
			elif read_obj is nc_client_sock:
				unpacked_message = crypto_mod.unpack_message(client_handle.socket_read(), secret_key, my_nonce)
                                if unpacked_message == -1:
                                        sys.exit(0)
                                print unpacked_message	

except KeyboardInterrupt:
	sys.exit(0)

except Exception as e:
	#print str(e)
	sys.exit(0)
