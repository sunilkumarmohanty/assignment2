import OpenSSL.SSL
import socket
import sys
import time
import ssl

  
def tf(val):
  if int(val) == 1:
    return True
  return False
  
def printcert(cert):
  print("SHA1 digest: " + cert.digest("sha1"))
  print("MD5  digest: " + cert.digest("md5"))
  print("\ncert details \n issuer: ")
  for (a,b) in cert.get_issuer().get_components():
    print("\t"+a+": "+b)
  print("pubkey type: "+str(cert.get_pubkey().type()))
  print("pubkey bits: "+str(cert.get_pubkey().bits()))
  print("serial:      "+str(cert.get_serial_number()))
  print("signalgo:    "+str(cert.get_signature_algorithm()))
  print("subject:")
  for (a,b) in cert.get_subject().get_components():
    print("\t"+a+": "+b)
  print("version:     "+str(cert.get_version()))
  print("not before:  "+str(cert.get_notBefore()))
  print("not after:   "+str(cert.get_notAfter()))
  
  print("\nextensions:")
  try:
    for i in xrange(0,cert.get_extension_count()-1):
      print(cert.get_extension(i))
  except OpenSSL.crypto.Error:
    pass
  
  print("#"*72)
  
if __name__  == "__main__":
  try:
    host = sys.argv[1]
  except:
    sys.exit(1)
  
  ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
  ctx.verify_mode = ssl.CERT_NONE
  
  if ":" in host and socket.has_ipv6 == True:
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
  else:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK,1)
  
  try:
    s.connect((host,443))
  except socket.error:
    print("can't connect")
  
  ssl = OpenSSL.SSL.Connection(ctx,s)

  #ssl.setblocking(True)
  
  #ssl = OpenSSL.SSL.Connection(ctx,s)
  try:
    ssl.set_connect_state()
    ssl.do_handshake()
    #print(ssl.get_cipher_list()
  except Exception:
    print(Exception)
  
  #s.shutdown(0)
  
  peercert = ssl.get_peer_certificate()
  peercertchain = ssl.get_peer_cert_chain()
  digest = peercert.digest('sha1').replace(":","").lower()
  
  print("peer cert:")
  printcert(peercert)
  
  print("\n\npeer cert chain:\n")
  for cert in peercertchain:
      printcert(cert)
