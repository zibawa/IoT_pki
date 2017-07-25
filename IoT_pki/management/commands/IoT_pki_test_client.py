#!/usr/bin/python
import time
from requests import Request, Session
import requests
import json
import sys
import os
import random
import string






def setup():       
    
        
        global pathToClientCert
        pathToClientCert="tempCert.pem"  
        
        #this is the ca_cert used for SSL of your server, (NOT the ca issuing the client certificates).  
        #if using letsencrypt of similar, then should not be necessary.
        global pathToCACert
        pathToCACert=True #True will use default cert store,(should be ok with lets encrypt or similar)
        # if using self signed you will need to replace with
        #pathToCACert="path/to/ca/cert"
        
        global pathToToken
        pathToToken="token.txt"#client needs to store a temporary token on file to retrieve certificate
        
        #each device must identify itself with unique common name to go on certificate
        #this must be different for each client device or user. For test purposes we generate random ID.
        #in practise you adopt your own strategy to assign unique common names to your devices
        global device_common_name 
        device_common_name= id_generator(5)#generate random ID each time we use
        
        global verify_certs
        verify_certs=True
        
        global host_name
        host_name= "app.zibawa.com"
        
        global port
        port=443
        
        
        
        
        #uncomment below to just test renew client cert
        #renewClientCert(pathToClientCert)
        #sys.exit(0)
          
        #for the purposes of the simulation we will remove the old cert and token file each time!
        try:
            os.remove(pathToClientCert)
            
        except:
            pass
        try:
            os.remove(pathToToken)
        except:
            pass    
        
        haveValidCertificate=False
        while (haveValidCertificate==False):
            haveValidCertificate=processRequest()
            time.sleep(5)
        
        
    
def processRequest():                    
        #tries to renew certificate if available, if not makes request to obtain new certificate
        #returns True if valid certificate availble
        
        
        if (renewClientCert(pathToClientCert)):
            return True
       
        try:
            token=readTokenFromFile()
            tokenIsValid=True
        except:
            tokenIsValid=False
            
        while tokenIsValid:
        #if we have a valid token we will try to collect certificate, until we get an invalid token response from the server
        #
            result=collectCertWithToken(token)
            if(result.status_code==201):
                os.remove(pathToToken)#remove used token
                print("collected cert with token - test renewal before exiting")
                #we should have valid cert here, but return False to force test renewal before exiting
                return False
            elif (result.status_code==404):
                print('token not found')
                tokenIsValid=False
                os.remove(pathToToken)
            else:
                #unapproved token requests return 403 token is kept
                print('token is not approved, go to admin panel and approve cert_request')
                return False
                    
                
            
        print('making new cert request')
        postdata={'common_name':device_common_name}
        headers = {'Accept': 'application/json',
                   'Content-Type' : 'application/json'}
    
        result=callPKI ('/IoT_pki/new_request/','POST',headers,postdata,)
        try:
            data=result.json()
        except:
            pass
        if (result.status_code==201):
            print('obtained request token')
            token=data['token']
            writeTokenToFile(token)
        else:
            print('unable to request new certificate')    
        return False


def renewClientCert(pathToClientCert):
    print('checking for presence of certificate file')
        
    if (os.path.isfile(pathToClientCert)):
        
        result=callPKI ('/IoT_pki/renew_cert/','GET')
        if (result.status_code==201):
            with open(pathToClientCert,"wb") as f:
                f.write(result.content)
                print('certificate renewed..exiting')
                return True
        
        elif (result.status_code==200):
            print('certificate valid but not due for renewal..exiting')
            return True
        else:
            print(result.content)        
    else:
        print('no client certificate found')
    return False

    
                
def writeTokenToFile(token):
    with open(pathToToken,"w") as f:
        f.write(token)
        f.close()

def readTokenFromFile():
    with open(pathToToken,"r") as f:
        token= f.read()
        f.close()
        print("token:%s",token)
        return token    
            
            
def collectCertWithToken(token):
        #returns result to allow us to decide what to do as function of status code
        apiurl="/IoT_pki/cert_collect/"+str(token)+"/"
        
        result=callPKI(apiurl,'GET')
        if (result.status_code==201):
            with open(pathToClientCert,'wb') as f:
      
    # write the contents of the response (r.content)
    # to a new file in binary mode.
                f.write(result.content)
                print('client certificate saved')
            
        return result
        

def callPKI(apiurl,callType,headers={},data={}):
    #function to make Curl call using requests library
       
    if verify_certs:
            #TO DO   need to distinguish between ca cert for ssl and pki!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        verifycerts= pathToCACert 
    else:
        verifycerts=False
                
    url='https://'+host_name+":"+str(port)+apiurl
    print('making %s request to pki %s',callType,url)
    #username= settings.PKI['user']
    #password= settings.PKI['password']
        
    s = Session()
    req = Request(callType,url,data=json.dumps(data),headers=headers)
    prepped = s.prepare_request(req)
    
    # if we have Client Cert use it
    if (os.path.isfile(pathToClientCert)):
        cert=pathToClientCert
    else:
        cert=None
        
    result = s.send(prepped,verify=verifycerts,cert=cert)
    print("status code received %s" , result.status_code)
            
    return result  



def id_generator(size=20, chars=string.ascii_uppercase + string.digits):
    
    return ''.join(random.choice(chars) for _ in range(size))



setup()


