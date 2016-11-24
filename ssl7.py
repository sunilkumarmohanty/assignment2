import OpenSSL.SSL
import socket
import sys
from ssl import match_hostname
from datetime import datetime
from binascii import hexlify
from OpenSSL import crypto
import requests
import locale
import urllib

def Verify_CRL_WithCert(link, cert):
    ret = True
    try:
        urllib.request.urlretrieve(link.decode(), "some.crl")
    except Exception as e:
        print(e)
        return True
    with open('some.crl', 'rb') as _crl_file:
        try:
            crl = b"".join(_crl_file.readlines())
        except Exception as e:
            print(e)
            return False

    crl_object = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, crl)
    try:
        revoked_objects = crl_object.get_revoked()
        c_serial = "%X" % (cert.get_serial_number(),)
        #print(c_serial)
        for rvk in revoked_objects:
            r_serial = rvk.get_serial().decode()
            if r_serial == c_serial:
                ret = False
                raise Exception("Certificate revoked")

    except Exception as e:
        ret = False
        print(e)

    return ret

def GetCRL(cert):
    try:
        for i in range(0,cert.get_extension_count()-1):
            if(cert.get_extension(i).get_short_name().find(b'crlDistributionPoints')!=-1):
                start = cert.get_extension(i).get_data().find(b'http')
                if start != -1:
                    return (cert.get_extension(i).get_data()[start:])
    except OpenSSL.crypto.Error:
      pass

def verifyCRL(cert):
    crlLink = GetCRL(cert)
    #print(crlLink)
    if crlLink:
        if Verify_CRL_WithCert(crlLink, cert) == False:
            return False

    return True



# uses HOST
def verify_cb(conn, x509, errno, errdepth, retcode):
    """
      callback for certificate validation
      should return true if verification passes and false otherwise
    """
    verify_cb.counter += 1
    print("=" * 25, "Start Certificate ", verify_cb.counter, "Data", "=" * 25)
    print("Certificate ", verify_cb.counter, ":")
    print("Issuer:")
    print("\t- Organization Name: ", x509.get_issuer().O)
    print("\t- Organization Unit: ",x509.get_issuer().OU)
    print("\t- Common Name: ", x509.get_issuer().CN)
    print("Subject:")
    print("\t- Organization Unit: ", x509.get_subject().O)
    print("\t- Organization Unit: ", x509.get_subject().OU)
    print("\t- Common Name: ", x509.get_subject().CN)
    print("\t - Expiry Date", x509.get_notAfter())
    print("=" * 25, "End Certificate ", verify_cb.counter, "Data", "=" * 25)



    if x509.has_expired() == True:
        exp_time = x509.get_notAfter().decode()
        print("Certificate has Expired. Expiration Date:",exp_time[:4],".",exp_time[4],exp_time[5],".",exp_time[6],exp_time[7])
        return False


    if verify_cb.cert_trust == False:

        #store = ctx.get_cert_store()
        #store = ctx.get_cert_store()


        storecontext = crypto.X509StoreContext(store, x509)

        try:
            if storecontext.verify_certificate() == None:
                verify_cb.cert_trust = True
                print("\nCertificate Has been Verified with Trusted CA Certificate List in the System\n")
        except Exception as e:
            print(e)
            print("Certificate Trust Cannot be Verified.")
            #return False

    if verifyCRL(x509) == False:
        print("Inside False")
        return False


    # Set the errno back to "0" , Since if we had to exit from a hard fault or Exception
    # We would have done so, Some Exceptions are excepted until the Last Certificate in the
    # Chain is Verified
    errno = 0;

    if errno == 0:
        if errdepth != 0:
          # don't validate names of root certificates
          return True
        else:

            if verify_cb.cert_trust == False:
                print("Certificate Trust Cannot be Verified")
                return False

          #Check for CRL Revocation

            dnsname = "*."+host
            if x509.get_subject().CN == host or x509.get_subject().CN == "*."+host or x509.get_subject().CN == "*."+dnsname.split('.', 1)[1]:
                return True
            else:
                str1 = x509.get_subject().CN
                print(x509.get_subject().CN)
                str1.split('.')
                print(str1.split('.'))
                print("Hostname Doesnt match Expected Hostname:" +host ,"Got:" +x509.get_subject().CN)
                #return False
                return False

    else:
        return False

# Static Varaibles of the Function
verify_cb.counter = 0
verify_cb.cert_trust = False


if __name__ == "__main__":
    try:
        host = sys.argv[1]
    except:
        sys.exit(1)

    ctx = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
    ctx.set_verify(OpenSSL.SSL.VERIFY_PEER | OpenSSL.SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb)
    ctx.load_verify_locations(None, "/etc/ssl/certs/")
    ctx.check_hostname = True
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.connect((host, 443))
    except socket.error:
        print ("can't connect")
        sys.exit(1)

    ssl = OpenSSL.SSL.Connection(ctx,s)
    ssl.setblocking(True)
    ssl.set_connect_state()

    try:
        ssl.set_connect_state()
        ssl.do_handshake()
    except Exception as e:
        print("Exception Raised from SSL Handshake", e)
        exit("[-] ssl handshake error")

    print("\nSSL Certificate Validtion Done!! Connected to the Host:", host, "\n")
    print("\nThe Webpage Content is as Follows:\n")
    r = requests.get('https://'+host)
    print("#" * 30, "Start Content", "#" * 30)
    print(r.content)
    print("#" * 30, "End Content", "#" * 30)

    s.shutdown(0)


    # Debug Code
    # To get and print the entire Peer  Certificate Chain - Dump the Ceriticate with all the Data
    # Uncommoent the below lines onle for debugging

    """
    peercert = ssl.get_peer_certificate()
    peercertchain = ssl.get_peer_cert_chain()
    digest = str(peercert.digest('sha1')).replace(":", "").lower()
    print ("\n\npeer cert chain:\n")
    for cert in peercertchain:
        print_Cert_Fields(cert)
    """

"""
def print_Cert_Fields(cert):
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
"""