from django.test import TestCase,Client
from django.contrib.auth.models import User
from django.utils import timezone
from .models import Cert_request,Certificate
import logging
import datetime
logger = logging.getLogger(__name__)
# Create your tests here.


 
    
    
    
        

class CreateCATestCase(TestCase):
#note test which start in capitals only run when called by a test starting in small letter
#this is to force the tests to run in sequence
    
    def test_create_ca(self):
               
        logger.info('test start test create ca ' )
        logger.info('test post')
        response=self.client.post('/IoT_pki/new_ca/', {'country_name': 'es','common_name':"autotestca",'not_valid_after':"2050-09-10 14:11:56"})
        #should redirect to login
        self.assertEqual(response.status_code, 302)
    
    
    
        
class TestAdmin(TestCase):

    def setUp(self):
        loginAsSuperUser(self)
          

        
    def test_create_and_download_CA_cert(self):    
        create_ca_as_admin(self)  
        logger.info('tests: download_CA_cert')
        response=self.client.get('/IoT_pki/download_ca/')
        self.assertEqual(response.status_code, 200)
        
    
                  
        
def loginAsSuperUser(self):
        #login as super user
        logger.info('test setup test admin')
        self.client = Client()
        self.my_admin = User(username='user', is_staff=True,is_superuser=True)
        self.my_admin.set_password('passphrase') # can't set above because of hashing
        self.my_admin.save() # needed to save to temporary test db
        response = self.client.get('/admin/', follow=True)
        loginresponse = self.client.login(username='user',password='passphrase')
        self.assertTrue(loginresponse) # should now return "true"
        logger.info('login response %s:',loginresponse)

def create_ca_as_admin(self):
    logger.info('test start test create as admin' )
        
    logger.info('test post')
    response=self.client.post('/IoT_pki/new_ca/', {'country_name': 'es','common_name':"autotestca",'not_valid_after':"2050-09-10 14:11:56"})
    self.assertEqual(response.status_code, 201)
        
class RequestAndCollecctTestCase(TestCase):
    
    def setUp(self):
        
        loginAsSuperUser(self)
        create_ca_as_admin(self)
        
        
    def test_request(self):
               
        logger.info('test start test request' )
        logger.info('test post')
        response=self.client.post('/IoT_pki/new_request/', {'country_name': 'es','common_name':"autotest",'not_valid_after':"2050-09-10 14:11:56"})
        self.assertEqual(response.status_code, 201)
    
            
    def test_collect(self):
        
        logger.info ('test cert_collect')
        request=Cert_request()
        request.common_name="autotestcollect"
        request.token="Test5token"
        request.approved=True
        request.save()
        response=self.client.get('/IoT_pki/cert_collect/BadToken/')
        self.assertEqual(response.status_code,404)
        url="/IoT_pki/cert_collect/Test5token/"
        response=self.client.get(url)
        self.assertEqual(response.status_code,201)
            


class RequestAndCollecctPkcs12TestCase(TestCase):
    #this is repeat of above but using pkcs12 format
    def setUp(self):
        
        loginAsSuperUser(self)
        create_ca_as_admin(self)
        
        
    def test_request(self):
               
        logger.info('test start test request' )
        logger.info('test post')
        response=self.client.post('/IoT_pki/new_request/', {'country_name': 'es','common_name':"autotest",'not_valid_after':"2050-09-10 14:11:56"})
        self.assertEqual(response.status_code, 201)
    
            
    def test_collect_pkcs12(self):
        
        logger.info ('test cert_collect_pkcs12')
        request=Cert_request()
        request.common_name="autotestcollectpkcs12"
        request.token="Test5tokenpkcs12"
        request.approved=True
        request.save()
        response=self.client.get('/IoT_pki/cert_collect/pkcs12/BadToken/')
        self.assertEqual(response.status_code,404)
        url="/IoT_pki/cert_collect/pkcs12/Test5tokenpkcs12/"
        response=self.client.get(url)
        self.assertEqual(response.status_code,201)
    
    def test_export_crl(self):
        logger.info ('test export crl')
        response=self.client.get('/IoT_pki/export_crl/')
        
        self.assertEqual(response.status_code,201)


  
        