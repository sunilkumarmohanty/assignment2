from ssl import wrap_socket, CERT_NONE, PROTOCOL_SSLv23
from ssl import SSLContext  # Modern SSL?
from ssl import HAS_SNI  # Has SNI?
from pprint import pprint
import socket

#Source - http://stackoverflow.com/questions/30862099/how-can-i-get-certificate-issuer-information-in-python

hostname = 'google.com'

#ctx = SSLContext(PROTOCOL_TLSv1)
ctx = SSLContext(2)
#ctx.verify_mode = CERT_REQUIRED
ctx.load_verify_locations(None, "/etc/ssl/certs/")

s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
s.connect((hostname, 443))

cert = s.getpeercert()
pprint(s.getpeercertchain())

#print(cert)


#print(ssl.enum_certificates("CA"))
#ctx.load_cert_chain()
#for key in cert.keys():
#  print(key)
#ctx.load_cert_chain()


subject = dict(x[0] for x in cert['subject'])
issued_to = subject['commonName']
print(issued_to)
issuer = dict(x[0] for x in cert['issuer'])
issued_by = issuer['commonName']
print(issued_by)
print(cert['caIssuers'])






