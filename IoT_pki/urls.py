from django.conf.urls import url,include
from . import views

#from rest_framework import routers 


#router = routers.DefaultRouter()
#router.register(r'users', views.UserViewSet)
#router.register(r'groups', views.GroupViewSet)

# Wire up our API using automatic URL routing.
# Additionally, we include login URLs for the browsable API.

urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^test_client_cert/$', views.test_client_cert, name='test_client_cert'),
    url(r'^renew_cert/$', views.renew_cert, name='renew_cert'),
    url(r'^new_ca/$', views.new_ca, name='new_ca'),
    url(r'^download_ca/$', views.download_ca, name='download_ca'),
    url(r'^new_request/$', views.New_request.as_view()),
    url(r'^cert_collect/(?P<token>[0-9A-Za-z]+)/$', views.cert_collect, name='cert_collect'),
    url(r'^cert_collect/pkcs12/(?P<token>[0-9A-Za-z]+)/$', views.cert_collect_pkcs12, name='cert_collect_pkcs12'),
    url(r'^export_crl/$', views.export_crl, name='export_crl'),
    
    
 #   url(r'^', include(router.urls)),
 #   url(r'^api-auth/', include('rest_framework.urls', namespace='rest_framework'))
   
]
