from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime
from django.utils import timezone
from django.conf import settings
from .helper_functions import id_generator
import logging
from .models import Certificate
import OpenSSL

logger = logging.getLogger(__name__)

def generateNewX509(cert_request):
    
    cert_data=prepareCert(cert_request) 
    streamedData=makeCert(cert_data)
    
    return streamedData
    #return "/home/jmm/myCA/certs/myPKIcert.pem"



def loadPEMCert(pathToCert):
    with open(pathToCert, 'rb') as f:
        crt_data = f.read()
        cert=x509.load_pem_x509_certificate(crt_data,default_backend())
        return cert
        

def loadPEMKey(pathToKey):
    with open(pathToKey, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
        )
    return private_key           


    
def certStorePath(id):
    return settings.PKI['path_to_certstore']+str(id)+".pem"

def keyStorePath(id):
    return settings.PKI['path_to_keystore']+str(id)+".key"
     

    
def copyAttrOrGetDefault(certificate, key,cert_request):
    #this function is used to copy cert request data to certificate object and if not available get defaults from settings
    try: 
        value=getattr(cert_request,key)
    except:
        #blank value will fail test below to look for default
        value=""
        
    #check also to see if value is blank
    if not value:
        try:
            value=settings.CERT_DEFAULTS[key]
            
        except:
            value="unknown"
    if not value:
        value="unknown"                 
    logger.info("value key%s value %s", key, value)
    setattr(certificate,key, value)
    return certificate
            

def prepareCert(cert_request):
    #copy data from cert_request or certificate ,add default data and save to certificates database
    #used for both New requests and renewals
    
    cert_data=Certificate()
    keys={'country_name','state_or_province_name','locality_name','organization_name','organization_unit_name','email_address','user_id','dns_name','common_name','dn_qualifier'}
    
    for key in keys:
        #copyattrorgetdefault only for text attributes
        copyAttrOrGetDefault(cert_data,key,cert_request)
    
    cert_data.is_ca=cert_request.is_ca
    cert_data.not_valid_before=timezone.now()-datetime.timedelta(1,0,0)
    cert_data.not_valid_after=cert_request.not_valid_after   
    cert_data.serial_number=x509.random_serial_number()
    cert_data.issuer_serial_number=get_issuer(cert_data).serial_number
    logger.info("random serial %s",cert_data.serial_number)
    cert_data.save()
            
    return cert_data

def get_issuer(cert_data):
    #if is ca then returns self otherwise newest ca
    if (cert_data.is_ca):
        return cert_data
    else:
        return get_newest_ca()

def get_newest_ca():
    #currently non ca cert will be signed by the most recently issued CA non revoked on file 
    #used also by build_crl
    #returns newest ca object
          
    newest_ca=Certificate.objects.filter(is_ca=True,revoked=False).order_by('-not_valid_before')[0]
    return newest_ca
            
    
    
    

def makeCert(cert_data):
    #given parameters for cert, returns bytes for certificate (private key and public key)
       
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
        )
    public_key = private_key.public_key()
        
    builder = x509.CertificateBuilder()
    subject=x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cert_data.common_name),
        x509.NameAttribute(NameOID.COUNTRY_NAME,cert_data.country_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,cert_data.state_or_province_name),
        x509.NameAttribute(NameOID.LOCALITY_NAME,cert_data.locality_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,cert_data.organization_name),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,cert_data.organization_unit_name),
        x509.NameAttribute(NameOID.USER_ID,cert_data.user_id),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS,cert_data.email_address),
        
        ])
    builder = builder.subject_name(subject)
    builder = builder.not_valid_before(cert_data.not_valid_before)
    builder = builder.not_valid_after(cert_data.not_valid_after)
    builder = builder.serial_number(cert_data.serial_number)
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        x509.SubjectAlternativeName(
            [x509.DNSName(cert_data.dns_name)]
            ),
            critical=False
        )
    
    
    #if CA
    
    if (cert_data.is_ca):
        
    
        builder = builder.issuer_name(subject)
        builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=2), critical=True,
        )
        builder = builder.add_extension(x509.KeyUsage(digital_signature=True,content_commitment=True,key_encipherment=True,key_agreement=False,data_encipherment=False,crl_sign=True,encipher_only=False,decipher_only=False,key_cert_sign=True),critical=True) 
        
        builder = builder.add_extension(x509.AuthorityInformationAccess([(x509.AccessDescription(x509.oid.AuthorityInformationAccessOID.OCSP,x509.UniformResourceIdentifier('https:ocsp.zibawa.com')))]),critical=False)
        
        certificate = builder.sign(
                private_key=private_key, algorithm=hashes.SHA256(),
                backend=default_backend()
                )
    #write certificate to pem file
        with open(certStorePath(cert_data.serial_number), "wb") as f:
        
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
    #write private key to pem file    
        with open(keyStorePath(cert_data.serial_number), "wb") as f:
            f.write (private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
                ))  
        #returns only public cert as datastream    
        dataStream=(certificate.public_bytes(serialization.Encoding.PEM))       
    
            
    else:
    
    #if NOT CA 
    
        builder = builder.issuer_name(loadPEMCert(certStorePath(cert_data.issuer_serial_number)).subject)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
            )
        builder = builder.add_extension(x509.KeyUsage(digital_signature=True,content_commitment=True,key_encipherment=True,key_agreement=False,data_encipherment=False,crl_sign=False,encipher_only=False,decipher_only=False,key_cert_sign=False),critical=True) 
    
        certificate = builder.sign(
            private_key=loadPEMKey(keyStorePath(cert_data.issuer_serial_number)), algorithm=hashes.SHA256(),
            backend=default_backend()
            )
    #if not CA return public AND private key        
        dataStream=private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
            )
        dataStream+=(certificate.public_bytes(serialization.Encoding.PEM))  
    
        
    return dataStream
    



def build_crl():
#from cryptography import x509
#    from cryptography.hazmat.backends import default_backend
#from cryptography.hazmat.primitives import hashes
#    from cryptography.hazmat.primitives.asymmetric import rsa
#from cryptography.x509.oid import NameOID
#import datetime
    ca=get_newest_ca()
    one_day = datetime.timedelta(1, 0, 0)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
        )
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,ca.common_name),
        ]))
    builder = builder.last_update(datetime.datetime.today())
    builder = builder.next_update(datetime.datetime.today() + one_day)
    revoked_cert = x509.RevokedCertificateBuilder().serial_number(
        333
        ).revocation_date(
            datetime.datetime.today()
            ).build(default_backend())
    
    revoked_list=Certificate.objects.filter(issuer_serial_number=ca.serial_number,revoked=True)
    revoked_cert = x509.RevokedCertificateBuilder().serial_number(444
                 ).revocation_date(
                     datetime.datetime.today()
                     ).build(default_backend())
    
    for revoked_cert in revoked_list:
        logger.debug("ca.serial_number: %s",revoked_cert.serial_number)
        revoked_cert = x509.RevokedCertificateBuilder().serial_number(int(revoked_cert.serial_number)
                 ).revocation_date(
                     datetime.datetime.today()
                     ).build(default_backend())
        builder = builder.add_revoked_certificate(revoked_cert)
    revoked_cert = x509.RevokedCertificateBuilder().serial_number(222
                 ).revocation_date(
                     datetime.datetime.today()
                     ).build(default_backend())    
    crl = builder.sign(
            private_key=loadPEMKey(keyStorePath(ca.serial_number)), algorithm=hashes.SHA256(),
            backend=default_backend()
            )
    
    dataStream=crl.public_bytes(serialization.Encoding.PEM)

    return dataStream



    


    
    


    
    
    
      