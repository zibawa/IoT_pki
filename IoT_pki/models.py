from __future__ import unicode_literals
from django.db import models
from django.utils import timezone
import datetime
from django.contrib.admin.utils import help_text_for_field
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.conf import settings
import logging
from .helper_functions import id_generator

# Create your models here.
logger = logging.getLogger(__name__)

class Cert_request (models.Model):
    
    #account = models.ForeignKey(User, on_delete=models.CASCADE,editable=False)#this is the administrative user that can approve request. Not used.
    country_name = models.CharField(max_length=2,blank=True )#obligatory must be 2 letter country code
    state_or_province_name=models.CharField(max_length=50, blank=True)
    locality_name=models.CharField(max_length=50,blank=True)
    organization_name=models.CharField(max_length=50,blank=True)
    organization_unit_name=models.CharField(max_length=50,blank=True)
    email_address=models.EmailField(blank=True)
    user_id=models.CharField(max_length=50,blank=True)
    dns_name=models.CharField(max_length=250,blank=True)
    common_name=models.CharField(max_length=50)
    dn_qualifier=models.CharField(max_length=250,blank=True)
    not_valid_after=models.DateTimeField(default=timezone.now()+datetime.timedelta(days=60))#used for ca only
    approved=models.BooleanField(default=False)
    issued=models.BooleanField(default=False)#to prevent same cert being downloaded twice
    request_time=models.DateTimeField(default=timezone.now)#
    token=models.CharField(max_length=50,db_index=True,default=id_generator(30))#token to allow cert collection
    is_ca=models.BooleanField(default=False)
    
    def save(self, *args, **kwargs):
        
        super(Cert_request, self).save(*args, **kwargs) # Call the "real" save() method.
        sendTokenByEmail(self)
    
    
    def __str__(self):
        return self.common_name

    
class Certificate (models.Model):
    
    #account = models.ForeignKey(User, on_delete=models.CASCADE,editable=False)
    country_name = models.CharField(max_length=2)
    state_or_province_name=models.CharField(max_length=50, blank=True)
    locality_name=models.CharField(max_length=50,blank=True)
    organization_name=models.CharField(max_length=50,blank=True)
    organization_unit_name=models.CharField(max_length=50,blank=True)
    email_address=models.EmailField(blank=True)
    user_id=models.CharField(max_length=50,blank=True)
    dns_name=models.CharField(max_length=250,blank=True)
    common_name=models.CharField(max_length=50,blank=True)
    dn_qualifier=models.CharField(max_length=250,blank=True)
    not_valid_before=models.DateTimeField()
    not_valid_after=models.DateTimeField()
    serial_number=models.CharField(max_length=250,db_index=True)
    revoked=models.BooleanField(default=False)
    is_ca=models.BooleanField(default=False,db_index=True)
    issuer_serial_number=models.CharField(max_length=250)
   
   
   
    
    def __str__(self):
        return self.common_name
    
def sendTokenByEmail(cert_request):
    
    #sends email if email defined on cert request when cert approved and not yet issued    
    if ((cert_request.email_address) and cert_request.approved and not cert_request.issued) :
        linkToCertificate= "https://"+settings.PKI['host']+"/IoT_pki/cert_collect/pkcs12/"+cert_request.token+"/"
        message= 'Your system administrator has approved a user certificate for you.  This will enable you to log in certain systems without requiring a password. To download the certificate, please follow the attatched link, or paste it into your browser.  '+ linkToCertificate
        logger.debug("message:%s",message)
        try:
            send_mail(
                'Your user certificate',
                message,
                settings.DEFAULT_FROM_EMAIL,
                [cert_request.email_address],
                fail_silently=False,
                )
        except:
            logger.warning("unable to send email to cert user: check mail configuration")    
    