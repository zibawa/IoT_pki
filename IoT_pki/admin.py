from django.contrib import admin
from IoT_pki.models import Cert_request,Certificate






class Cert_requestAdmin(admin.ModelAdmin):
    list_display=('common_name','email_address','dns_name','request_time','issued','approved')
    search_fields=['common_name','email_address','dns_name']
    list_filter = ('approved','issued', 'is_ca','request_time')
    actions = ['make_approved']
    
    def make_approved(self, request, queryset):
        queryset.update(approved=True)
    make_approved.short_description = "Approve selected cert request"

class CertificateAdmin(admin.ModelAdmin):
    
    list_display=('common_name','email_address','dns_name','revoked','not_valid_after','is_ca')
    search_fields=['common_name','email_address','dns_name']
    readonly_fields = [
        'common_name','country_name','state_or_province_name','locality_name',
        'organization_name','organization_unit_name','email_address',
        'user_id','dns_name','dn_qualifier','not_valid_before','not_valid_after',
        'serial_number','is_ca','issuer_serial_number'
    ]
    list_filter = ('revoked', 'is_ca','not_valid_after','issuer_serial_number')
    actions = ['make_revoked']
    
    def make_revoked(self, request, queryset):
        queryset.update(revoked=True)
    make_revoked.short_description = "Add selected certificate to CRL "

admin.site.register(Certificate,CertificateAdmin)
admin.site.register(Cert_request,Cert_requestAdmin)