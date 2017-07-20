


from django.conf.urls import include, url
from django.contrib import admin

from django.conf.urls import url, include
from rest_framework import routers
from rest_framework.documentation import include_docs_urls
from IoT_pki import views

router = routers.DefaultRouter()



urlpatterns = [
    
    
    url(r'^admin/', admin.site.urls),
    url(r'^IoT_pki/', include('IoT_pki.urls',namespace='IoT_pki')),
    url(r'^', include(router.urls)),
    url(r'^api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    url(r'^docs/', include_docs_urls(title='zibawa_PKI'))
    
    
    
]

