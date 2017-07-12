from django.contrib import admin
from IoT_pki.models import Cert_request,Certificate

# Register your models here.
class Cert_requestAdmin(admin.ModelAdmin):
    list_display=('id','common_name','dns_name','approved')
    pass

class CertificateAdmin(admin.ModelAdmin):
    list_display=('id','common_name','dns_name')
    pass

    


admin.site.register(Certificate,CertificateAdmin)
admin.site.register(Cert_request,Cert_requestAdmin)