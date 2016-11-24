import OpenSSL.SSL
import socket
import sys
#import dns.resolver
import time
#from backports.ssl_match_hostname import match_hostname, CertificateError
#import urllib3
import urllib
from ssl import match_hostname
from datetime import datetime
from binascii import hexlify
from OpenSSL import crypto
import re
#import requests
import locale

def days2ctime(days):
  return time.strftime("%Y-%m-%d",time.localtime(days * 86400))

def tf(val):
  if int(val) == 1:
    return True
  return False

def printcert(cert):
  #print ("SHA1 digest: " + str(cert.digest("sha1")))
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
      print (cert.get_extension(i))
  except OpenSSL.crypto.Error:
    pass

  print ("#"*72)


def CheckCRL(link, cert):
    print("inside CRL")
    print(link)
    testfile = urllib.URLopener()
    testfile.retrieve(link, "some.crl")
    with open('some.crl', 'r') as _crl_file:
        crl = "".join(_crl_file.readlines())
    print("1")
    crl_object = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, crl)
    revoked_objects = crl_object.get_revoked()
    print(cert.get_serial_number())
    c_serial = "%X" % (cert.get_serial_number(),)
    for rvk in revoked_objects:
        r_serial = rvk.get_serial()
        #print("inside for")
        if r_serial == c_serial:
            print("Certificate Revoked")
            return False

    return True
            #raise Exception("Certificate revoked")


def GetCRL(cert):

    try:
        for i in range(0,cert.get_extension_count()-1):
            #print cert.get_extension("crlDistributionPoints")
            if(cert.get_extension(i).get_short_name().find('crlDistributionPoints')!=-1):
                start = cert.get_extension(i).get_data().find("http")
                return (cert.get_extension(i).get_data()[start:])
    except OpenSSL.crypto.Error:
      pass

# uses HOST
def verify_cb(conn, x509, errno, errdepth, retcode):
    """
      callback for certificate validation
      should return true if verification passes and false otherwise
    """
    verify_cb.counter += 1
    print("Certificate ", verify_cb.counter, ":")
    print("Issuer:")
    print("\t- Organization Name: ", x509.get_issuer().O)
    print("\t- Organization Unit: ",x509.get_issuer().OU)
    print("\t- Common Name: ", x509.get_issuer().CN)
    print("Subject:")
    print("\t- Organization Unit: ", x509.get_subject().O)
    print("\t- Organization Unit: ", x509.get_subject().OU)
    print("\t- Common Name: ", x509.get_subject().CN)

    #crlLink = GetCRL(x509)
    #print("Hello")
    #print(crlLink)
    #if (crlLink):
    #    if CheckCRL(crlLink, x509) == False:
    #       return False


    # Files to verify
    #crlfile = r"path\to\crlfile"
    #mycacert = r"path\to\mycacert"
    # Set up args
    #args = ["openssl", "crl", "-inform", "DER", "-in", crlfile, "-CAfile", mycacert, "-noout"]
    # Run the thing
    #output = subprocess.check_output(args)
    #verified = True if output.upper() == "VERIFY OK" else False

    print("after CRL")
    if x509.has_expired() == True:
        exp_time = x509.get_notAfter().decode();

        #"{:%B %d, %Y}".format(x509.get_notAfter().decode())
        print("Certificate has Expired. Expiration Date:",exp_time[:4],".",exp_time[4],exp_time[5],".",exp_time[6],exp_time[7])
        return False
    if errno == 0:
        if errdepth != 0:
          # don't validate names of root certificates
          return True
        else:
          if x509.get_subject().CN == host:
            return True
          else:
            
            print("Hostname Doesnt match Expected Hostname: " +host ,"Got:" +x509.get_subject().CN)
            return False
    else:
        return False

verify_cb.counter = 0


if __name__  == "__main__":
  try:
    host = sys.argv[1]
  except:
    sys.exit(1)


  #ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
  #ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
ctx = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
ctx.set_verify(OpenSSL.SSL.VERIFY_PEER | OpenSSL.SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb)
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


try:
    ssl.set_connect_state()
    ssl.do_handshake()
    #print ssl.get_cipher_list()
except:
    exit("[-] ssl handshake error")

#ssl.do_handshake()

s.shutdown(0)

peercert = ssl.get_peer_certificate()


peercertchain = ssl.get_peer_cert_chain()
  #digest = peercert.digest('sha1')
  #digest = str(digest)
digest = str(peercert.digest('sha1')).replace(":", "").lower()
  #digest = "hello world"
  #digest = str.encode(digest)
type(digest)  # ensure it is byte representation



#print ("peer cert:")
#printcert(peercert)

#print ("\n\npeer cert chain:\n")
#for cert in peercertchain:
#    printcert(cert)


  #r = requests.get('https://www.google.com')
  #print(r.conte
