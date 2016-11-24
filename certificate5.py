import socket, ssl

from ssl import wrap_socket, CERT_NONE, PROTOCOL_SSLv23
from ssl import SSLContext  # Modern SSL?
from ssl import HAS_SNI  # Has SNI?

from pprint import pprint
def callback(ssl_socket, host, context):
	#print(context.get_ca_certs())
	print('##########################')
	pprint(ssl_socket.getpeercert())

def ssl_wrap_socket(sock, keyfile=None, certfile=None, cert_reqs=None,
                    ca_certs=None, server_hostname=None,
                    ssl_version=None):
    context = SSLContext(ssl_version)
    context.verify_mode = ssl.CERT_NONE
    context.load_verify_locations(None, "/etc/ssl/certs/")
    #context.set_servername_callback(callback)
    sockk = context.wrap_socket(sock)

    return (context, sockk)

hostname = 'www.google.com'
print("Hostname: %s" % (hostname))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#s.do_handshake()
s.connect((hostname, 443))
(context, ssl_socket) = ssl_wrap_socket(s,
                                       ssl_version=2,
                                       cert_reqs=2,
                                       ca_certs='/etc/ssl/certs/',
                                       server_hostname=hostname)




s.close()
