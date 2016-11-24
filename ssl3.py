import OpenSSL.SSL
from binascii import hexlify
from OpenSSL import crypto
import socket
import sys
#import dns.resolver
import time
import urllib
#from backports.ssl_match_hostname import match_hostname, CertificateError
#import urllib3
#from ssl import match_hostname
#import requests
def CheckCRL(link):
    #print link
    testfile = urllib.URLopener()
    testfile.retrieve(link, "some.crl")
    with open('some.crl', 'r') as _crl_file:
        crl = "".join(_crl_file.readlines())
    crl_object = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, crl)
    revoked_objects = crl_object.get_revoked()
    c_serial = "%X" % (cert.get_serial_number(),)
    for rvk in revoked_objects:
        r_serial = rvk.get_serial()
        if r_serial == c_serial:
            raise Exception("Certificate revoked")


def GetCRL(cert):

    try:
        for i in range(0,cert.get_extension_count()-1):
            #print cert.get_extension("crlDistributionPoints")
            if(cert.get_extension(i).get_short_name().find('crlDistributionPoints')!=-1):
                start = cert.get_extension(i).get_data().find("http")
                return (cert.get_extension(i).get_data()[start:])
    except OpenSSL.crypto.Error:
      pass
def days2ctime(days):
  return time.strftime("%Y-%m-%d",time.localtime(days * 86400))

def tf(val):
  if int(val) == 1:
    return True
  return False

def printcert(cert):
  #print ("SHA1 digest: " + str(cert.digest("sha1")))
  #print("CRL : "+ cert.get_extension())
  print("SHA1 digest: " + cert.digest("sha1").decode())
  print("MD5  digest: " + cert.digest("md5").decode())
  print( "\ncert details\nissuer: ")
  for (a,b) in cert.get_issuer().get_components():
    print("\t"+a.decode()+": "+b.decode())
  print ("pubkey type: "+str(cert.get_pubkey().type()))
  print ("pubkey bits: "+str(cert.get_pubkey().bits()))
  print ("serial:      "+str(cert.get_serial_number()))
  print ("signalgo:    "+cert.get_signature_algorithm().decode())
  print ("subject:")
  for (a,b) in cert.get_subject().get_components():
    print ("\t"+a.decode('utf-8')+": "+b.decode('utf-8'));
  print ("version:     "+str(cert.get_version()))
  print ("not before:  "+cert.get_notBefore().decode())
  print ("not after:   "+cert.get_notAfter().decode())

  print ("\nextensions:")
  try:
    for i in range(0,cert.get_extension_count()-1):
      print ("Extension : "+ str(i))
      print (cert.get_extension(i))
  except OpenSSL.crypto.Error:
    pass

  print ("#"*72)

if __name__  == "__main__":
  try:
    host = sys.argv[1]
  except:
    sys.exit(1)

  #ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
  #ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
  ctx = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
  ctx.load_verify_locations(None, "/etc/ssl/certs/")
  ctx.check_hostname = True

  #ctx.ver

#  if ":" in host and socket.has_ipv6 == True:
#    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
#  else:

  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 # s.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK,1)

  try:
    s.connect((host,443))
  except socket.error:
    print ("can't connect")
    sys.exit(1)

  ssl = OpenSSL.SSL.Connection(ctx,s)
  ssl.setblocking(True)
  ssl.set_connect_state()

  """
  try:
    ssl.set_connect_state()
    ssl.do_handshake()
    #print ssl.get_cipher_list()
  except:
    exit("[-] ssl handshake error")
  """
  ssl.do_handshake()
  s.shutdown(0)
  #print(ssl.get_context().get_cert_store()[0])
  #peercert = ssl.get_peer_certificate()
  #print(peercert.get_subject().CN)
  peercertchain = ssl.get_peer_cert_chain()

  print ("peer cert:")
  print ("\n\npeer cert chain:\n")
  for cert in peercertchain:
      #print(cert)
      printcert(cert)
      crlLink= GetCRL(cert)
      if(crlLink):
          CheckCRL(crlLink)

      if(cert.has_expired()):
          print("Exiting due to error. Certificate expired on : " + cert.get_notAfter())
          sys.exit(1)
