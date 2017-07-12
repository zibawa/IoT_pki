


from django.conf.urls import include, url
from django.contrib import admin

from django.conf.urls import url, include
from rest_framework import routers
from rest_framework.documentation import include_docs_urls
from IoT_pki import views

router = routers.DefaultRouter()

#router.register(r'cert_request', views.cert_request)
#router.register(r'get_approved_cert',views.get_approved_cert)

# Wire up our API using automatic URL routing.
# Additionally, we include login URLs for the browsable API.
urlpatterns = [
    url(r'^', include(router.urls)),
    url(r'^api-auth/', include('rest_framework.urls', namespace='rest_framework'))
]


urlpatterns = [
    
    
    url(r'^admin/', admin.site.urls),
    url(r'^IoT_pki/', include('IoT_pki.urls',namespace='IoT_pki')),
    url(r'^', include(router.urls)),
    url(r'^api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    url(r'^docs/', include_docs_urls(title='zibawa_PKI'))
    
    
    
]

