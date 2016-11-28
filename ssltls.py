"""
Author  : Sunil Kumar Mohanty
Course  : Network Security
Purpose : SSL/TLS validation check as per Assignment 2
"""



import OpenSSL.SSL
import socket
import sys
import time
import urllib
from ssl import match_hostname
from datetime import datetime
from binascii import hexlify
from OpenSSL import crypto
import requests
import locale
import subprocess


def tf(val):
  if int(val) == 1:
    return True
  return False

def PrintCertificate(x509):
    print("Certificate ", VerifyCertificate.counter, ":")
    print("Issuer:")
    print("\t- Organization name: ", x509.get_issuer().O)
    print("\t- Organization unit: ", x509.get_issuer().OU)
    print("\t- Common name: ", x509.get_issuer().CN)
    print("Subject:")
    print("\t- Organization name: ", x509.get_subject().O)
    print("\t- Organization unit: ", x509.get_subject().OU)
    print("\t- Common name: ", x509.get_subject().CN)
    print("===============================================")
    # print(x509.get_notAfter()

def CheckName(x509):
    try:
        dnsname = hostname
        cname = x509.get_subject().CN

        if cname == hostname or cname == "*." + hostname or cname == "*." + dnsname.split('.', 1)[1]:
            return True
        else:
            try:
                for i in range(0, x509.get_extension_count() - 1):
                    dnsstart = x509.get_extension(i).get_short_name().find(b'subjectAltName')
                    if (dnsstart != -1):
                        altnames = str(x509.get_extension(i)).split("DNS:")
            except Exception as e:
                print(e)

            for name in altnames:
                cname = name.replace(",","").strip()
                if cname == hostname or cname == "*." + hostname or cname == "*." + dnsname.split('.', 1)[1]:
                    return True
            return False
    except Exception as e:
        return False

def CheckCRL(link, cert):
    return_flag = True
    try:
        urllib.request.urlretrieve(link.decode(), "certificate.crl")
    except Exception as e:
        return True
    with open('certificate.crl', 'rb') as _crl_file:
        try:
            crl = b"".join(_crl_file.readlines())
        except Exception as e:
            return True

    crl_object = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, crl)
    try:
        revoked_objects = crl_object.get_revoked()
        c_serial = "%X" % (cert.get_serial_number(),)
        for rvk in revoked_objects:
            r_serial = rvk.get_serial().decode()
            if r_serial == c_serial:
                return_flag = False
                #raise Exception("Certificate revoked")
    except Exception as e:
        return_flag = True
        print(e)
    return return_flag


def DownloadCRL(cert):
    try:
        for i in range(0,cert.get_extension_count()-1):
            if(cert.get_extension(i).get_short_name().find(b'crlDistributionPoints')!=-1):
                start = cert.get_extension(i).get_data().find(b'http')
                if start != -1:
                    return (cert.get_extension(i).get_data()[start:])
    except OpenSSL.crypto.Error:
      pass

def VerifyCRL(cert):
    crlLink = DownloadCRL(cert)
    if crlLink:
        return CheckCRL(crlLink, cert)
    return True



# uses HOST
def VerifyCertificate(conn, x509, errno, errdepth, retcode):
    VerifyCertificate.counter += 1
    PrintCertificate(x509)
    if x509.has_expired() == True:
        exp_time = x509.get_notAfter().decode()
        expire_date = datetime.strptime(exp_time, "%Y%m%d%H%M%SZ")
        #print(expire_date)
        print("Exiting due to error: Certificate expired on ",expire_date)
        return False

    if VerifyCertificate.cert_trust == False:
        store = ctx.get_cert_store()
        storecontext = crypto.X509StoreContext(store, x509)
        try:
            if storecontext.verify_certificate() == None:
                VerifyCertificate.cert_trust = True
        except Exception as e:
            print("Certificate is not trusted")
            return False

    # Check for CRL Revocation

    crlVerification  = VerifyCRL(x509)
    if crlVerification == False:
        print("Certificate revoked")
        return False
    errno = 0
    if errno == 0:
        if errdepth != 0:
          # don't validate names of root certificates
          return True
        else:

            if VerifyCertificate.cert_trust == False:
                print("Certificate Trust Cannot be Verified")
                return False

            if(CheckName(x509)==False):
                print("Exiting due to error: Common name does not match host, expected : " + hostname + " got : " + x509.get_subject().CN)
                return False
            else:
                return True
    else:
        return False

VerifyCertificate.counter = 0
VerifyCertificate.cert_trust = False

if __name__  == "__main__":
  try:
    hostname = sys.argv[1]
    port = int(sys.argv[2])
  except:
    sys.exit(1)
ctx = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
ctx.set_verify(OpenSSL.SSL.VERIFY_PEER | OpenSSL.SSL.VERIFY_FAIL_IF_NO_PEER_CERT, VerifyCertificate)
ctx.load_verify_locations(None, "/etc/ssl/certs/")
ctx.check_hostname = True

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect((hostname, port))
except socket.error:
    print ("can't connect")
    sys.exit(1)

try:
    ssl = OpenSSL.SSL.Connection(ctx,s)
    ssl.setblocking(True)
    ssl.set_connect_state()
    ssl.do_handshake()

except Exception as e:
    print(e)
    exit("[-] ssl handshake error")
    sys.exit(0)

try:
    r = requests.get('https://'+hostname)
except Exception as ex:
    print("Exiting due to error:", ex)
    exit()

print(r.content)
r.close()
s.shutdown(0)
