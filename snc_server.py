import argparse
import socket
import select 
import sys
from snc_lib import snc_crypto_module, socket_handler, message_wrapper 

#Parse the incoming arguments
snc_parser = argparse.ArgumentParser(description='Secure netcat server')

snc_parser.add_argument('--key', metavar='my_secret_key', nargs=1, help="Secret key used to verify the authenticity of client's messages")

snc_parser.add_argument('-l', metavar='server_port_number', type=int, nargs=1, help='The port number on which the server listens' )

snc_args = snc_parser.parse_args()

secret_key, server_port = snc_args.key[0], snc_args.l[0]

#Initialize crypto module and generate key, nonce
c_module = snc_crypto_module()
secret_key = c_module.gen_pbkdf(secret_key)
my_nonce = c_module.gen_nonce(32)

#Socket creation (TCP)
nc_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

nc_server_socket.bind((socket.gethostname(), server_port))

nc_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

nc_server_socket.listen(1)


try:
	crypto_mod = snc_crypto_module()
	client_sock, client_addr = nc_server_socket.accept()
	inputs = [sys.stdin, client_sock]
	client_handle = socket_handler(client_sock)
	outputs = []
	while 1:
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
	                elif read_obj is client_sock:
	                        unpacked_message = crypto_mod.unpack_message(client_handle.socket_read(), secret_key, my_nonce)
	                        if unpacked_message == -1:
					sys.exit(0)
				print unpacked_message

except Exception as e:
        #print str(e)
	sys.exit(0)

except KeyboardInterrupt:
	sys.exit(0)
