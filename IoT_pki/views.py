from django.shortcuts import render
from django.forms import modelformset_factory
from django.http import HttpResponse,HttpResponseNotFound
from django.template.response import TemplateResponse
from django.template import loader, RequestContext
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import user_passes_test
from .x509_functions import generateNewX509,id_generator,makeCert,prepareCert,build_crl,certStorePath,get_newest_ca
from django.contrib.auth.models import User, Group
from .models import Cert_request,Certificate
from .forms import Ca_Form
from rest_framework import viewsets
from .serializers import Cert_requestSerializer
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import generics
from rest_framework import permissions
from rest_framework import serializers
from django.utils import timezone
from django.conf import settings
from django.shortcuts import get_object_or_404
import datetime
from .permissions import IsOwnerOrReadOnly,Anonymous
import logging
import OpenSSL

logger = logging.getLogger(__name__)
# Create your views here.



class New_request(generics.CreateAPIView):
    #this function generates a request for new certificate according to info supplied + system defaults
    #validation is carried out as defined below.
    
    model=Cert_request
    serializer_class=Cert_requestSerializer
    
    #don't forget to leave comma at end of permission_classes!
    permission_classes = (permissions.AllowAny,)
    
    def perform_create(self, serializer):
        #here we could add other info such as IP address 
        #Prevent duplicate requests for same common name
        queryset = Cert_request.objects.filter(common_name=serializer.validated_data['common_name'])
        if queryset.exists():
            pass
            ##need to uncomment in production !!!!
            #raise serializers.ValidationError('Duplicate Common Name in Cert requests')
        #prevent requests for common name where valid certificate has already been issued 
        queryset = Certificate.objects.filter(common_name=serializer.validated_data['common_name'],revoked=False,not_valid_after__gt=(timezone.now()))
        if queryset.exists():
            
            raise serializers.ValidationError('Valid certificate already issued')
        #generate random token to be returned to user to enable certificate collection 
          
        serializer.save(token=id_generator(),approved=settings.PKI['auto_approve_requests'])
        


def cert_collect(request,token):
    #when supplied with token, looks up request, checks approval status and returns appropriate HttpResponse
    
    certs = Cert_request.objects.filter(token=token)
       
    try:
        cert_request=certs[0]
    except:
        return HttpResponse(status=404,content="Bad token")    
    
    logger.info("retrieved cert %s",cert_request.common_name)
    
    if (cert_request.issued==True):
        logger.info("Certificate already issued %s",cert_request.common_name)
        response= HttpResponse(status=410,content="Cert already issued")
    elif (cert_request.approved==False):
        logger.debug("Certificate pending approval %s",cert_request.common_name)
        response=HttpResponse(status=403, content="Pending approval")         
    else:    
        logger.info("Generating cert %s",cert_request.common_name)
        dataStream=generateNewX509(cert_request)
  
        response = HttpResponse(dataStream, content_type='application/x-pem-file',status=201)
        response['Content-Disposition'] = 'attachment; filename="client_cert.pem"'
        #update cert_request to avoid duplicates being created
        cert_request.issued=True
        cert_request.save()
    

    
    return response 

def cert_collect_pkcs12(request,token):
    #when supplied with token, looks up request, checks approval status and returns appropriate HttpResponse
    #in this case token is taken from browser
    
    
    certs = Cert_request.objects.filter(token=token)
       
    try:
        cert_request=certs[0]
    except:
        return HttpResponse(status=404,content="Not found")    
    logger.info("retrieved cert %s",cert_request.common_name)
    
    if (cert_request.issued==True):
        logger.info("Certificate already issued %s",cert_request.common_name)
        response= HttpResponse(status=410,content="Cert already issued")
    elif (cert_request.approved==False):
        logger.debug("Certificate pending approval %s",cert_request.common_name)
        response=HttpResponse(status=403, content="Pending approval")         
    else:    
        logger.info("Generating cert %s",cert_request.common_name)
        datastream=generateNewX509(cert_request)
        
        c=OpenSSL.crypto
        cert=c.load_certificate(c.FILETYPE_PEM, datastream)
        key=c.load_privatekey(c.FILETYPE_PEM, datastream)
        p12 = OpenSSL.crypto.PKCS12()
        p12.set_privatekey(key)
        p12.set_certificate(cert)
        #open( "container.pfx", 'w' ).write( p12.export() )
        p12dataStream=p12.export()
  
        response = HttpResponse(p12dataStream, content_type='application/x-pkcs12',status=201)
        response['Content-Disposition'] = 'attachment; filename="client_cert.p12"'
        #update cert_request to avoid duplicates being created
        #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!uncomment below!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        #cert_request.issued=True
        cert_request.save()
    

    
    return response 






@user_passes_test(lambda u: u.is_superuser)
def new_ca(request):
#this sets up new CA which will be used in all future signing requests

    if request.method == 'POST':
        form = Ca_Form(request.POST)
        
        if form.is_valid():
            logger.debug("form is valid")
            ca_cert_request=form.save()
            ca_cert_request.is_ca=True
            new_ca_data=prepareCert(ca_cert_request)
            dataStream=makeCert(new_ca_data)
            response = HttpResponse(dataStream, content_type='application/x-pem-file',status=201)
            response['Content-Disposition'] = 'attachment; filename="client_cert.pem"'
            new_ca_data.issued=True
            new_ca_data.save()
        else:
            logger.debug("form not valid")
            return render(request, 'IoT_pki/new_ca.html', {'form': form})
        return response
            
            
            #copyID to "current CA file"
    else:
        form = Ca_Form()
    return render(request, 'IoT_pki/new_ca.html', {'form': form})
    return


def download_ca(request):
    #download public key for CA.         
    
    try:
        file = open(certStorePath(get_newest_ca().issuer_serial_number), 'r')
        file.seek(0)
        cert = file.read()
        file.close()
        response = HttpResponse(cert, content_type='application/x-pem-file',status=200)
        response['Content-Disposition'] = 'attachment; filename="ca_cert.pem"'
    
    except:
        response= HttpResponse(status=404, content= 'Not found you must create a CA first')
    
    
    return response 


def test_client_cert(request):
    try:
        client_verify=request.META['HTTP_X_SSL_AUTHENTICATED']
        logger.info ("client verified %s",client_verify)
    except:
        return HttpResponse (status=501,content="Didn't receive any ssl authenticated header from web server.  You must use https.  If you did, and the error persists, possible bad configuration of webserver")
    
    
    if (request.META['HTTP_X_SSL_AUTHENTICATED'])=="SUCCESS":
        user_dn=request.META['HTTP_X_SSL_USER_DN']
        logger.info("user_dn:%s",user_dn)
        hex_serial_number=request.META['HTTP_X_SSL_CLIENT_SERIAL']  
        logger.info("serial no:%s ",hex_serial_number)   
        content=request.META['HTTP_X_SSL_AUTHENTICATED'] + ": Zibawa PKI succesfully verified your certificate.  Serial number:"+hex_serial_number
        return HttpResponse (status=200,content=content)
        #return HttpResponse (status=200 ,content="200 - Certificate Valid, not yet due for renewal")
    
    else:
        #will return reason for failure provided by NGINX    
        return HttpResponse (status=403 ,content="Zibawa PKI has been unable to verify your client certificate:"+request.META['HTTP_X_SSL_AUTHENTICATED'])
    


def renew_cert(request):
    
    #obtains authentication status and cert serial no from NGINX proxy. 
    #if nginx verify is OK, not revoked, and serial number on database
    #returns appropriate http response
   
    try:    
        client_verify=request.META['HTTP_X_SSL_AUTHENTICATED']
        logger.info ("client verified %s",client_verify)
    except:
        return HttpResponse (status=501,content="Didn't receive any ssl authenticated header from web server.  You must use https.  If you did, and the error persists, possible bad configuration of webserver")
    
    if (request.META['HTTP_X_SSL_AUTHENTICATED'])=="SUCCESS":
        user_dn=request.META['HTTP_X_SSL_USER_DN']
        logger.info("user_dn:%s",user_dn)
        hex_serial_number=request.META['HTTP_X_SSL_CLIENT_SERIAL']  
        logger.info("serial no:%s ",hex_serial_number)   
        response=check_renewal_status(hex_serial_number)
        return response
        #return HttpResponse (status=200 ,content="200 - Certificate Valid, not yet due for renewal")
    
    else:
        #will return reason for failure provided by NGINX    
        return HttpResponse (status=403 ,content="not authorized client cert:"+request.META['HTTP_X_SSL_AUTHENTICATED'])
    
def check_renewal_status(hex_serial_number):
    
    
    #checks certificate serial number against DB, checks whether due for renewal
    #returns http response
    
    serial_number= int(hex_serial_number, 16)
    certs = Certificate.objects.filter(serial_number=serial_number)
    try:
        current_cert=certs[0]
        logger.info("cert found on database:%s ",current_cert.common_name)   
    except:
        logger.info("serial not found on database %s",serial_number)
        return HttpResponse (status=404, content="serial no not found on database")
    if (current_cert.revoked):
        logger.info("certificate revoked%s" , serial_number)
        return HttpResponse (status=404, content="certificate revoked")    
    
    delta = current_cert.not_valid_after - timezone.now()
    
    if (delta.days>settings.CERT_DEFAULTS['min_days_remaining_for_renewal']):
        logger.info("certificate due for renewal in days:%s",delta.days)
        return HttpResponse (status=200 ,content="200 - Certificate Valid, not yet due for renewal")
    else:
        logger.info("renewing certificate")
        renewed_cert=prepareCert(current_cert)
        dataStream=makeCert(renewed_cert)
        response = HttpResponse(dataStream, content_type='application/x-pem-file',status=201)
        response['Content-Disposition'] = 'attachment; filename="client_cert.pem"'
        renewed_cert.issued=True
        renewed_cert.save()
        
        return response


def export_crl(request):
    logger.debug("view export crl")
    #try:
    if 1==1:
        datastream= build_crl()
        response = HttpResponse(datastream, content_type='application/x-pem-file',status=201)
        response['Content-Disposition'] = 'attachment; filename="crl.pem"'
    '''
    except:
        response= HttpResponse(status=404, content= 'Not found')
    '''
    
    return response 
    

    
 
def index(request):
    template = loader.get_template('IoT_pki/pki_index.html')
    
    context = {
         'content':"",
         'has_permission':request.user.is_authenticated,
         'is_popup':False,
         'title':'IoT_pki',
         'site_title':'zibawa',
         
         
    }
    return HttpResponse(template.render(context, request))
