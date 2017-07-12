from django.forms import ModelForm
from .models import Cert_request
from django import forms

# Create the form class.
class Ca_Form(ModelForm):
    
    #not_valid_after= forms.DateTimeField(widget=forms.SelectDateWidget())
    
    class Meta:
        model = Cert_request
        fields = ['country_name', 'common_name','state_or_province_name','locality_name','organization_name','organization_unit_name','email_address','user_id','dns_name','common_name','dn_qualifier','not_valid_after']
        