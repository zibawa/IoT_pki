from rest_framework import serializers
from .models import Cert_request



        
class Cert_requestSerializer(serializers.HyperlinkedModelSerializer):
	class Meta:
		model = Cert_request
		fields = ('country_name','state_or_province_name','locality_name','organization_name','organization_unit_name','email_address','dns_name','common_name','dn_qualifier','approved','token')
		read_only_fields = ('approved','token')
		lookup_field='token'
		
        