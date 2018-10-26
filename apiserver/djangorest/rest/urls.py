from django.conf.urls import url
from django.urls import path, include
from . import views
from rest_framework import routers


router = routers.SimpleRouter()
router.register(r'customers', views.CustomerListCreateAPIView, base_name="Customers")     # đăng ký API vào router
router.register(r'certificates', views.CertificateListCreateAPIView, base_name="Certificates")
router.register(r'customers', views.CustomerDetailUpdateAPIView, base_name="Customers-detail")
router.register(r'certificates', views.CertificateDetailUpdateAPIView, base_name="Certificates-detail")
urlpatterns = [
    # url(r'^chg/(?P<domain>\w+)$', views.show_challenge, name='challenges'),
    url(r'^reg/$', views.auth_domain, name='auth_domain'),
    url(r'^verify/$', views.verify_auth, name='verify_domain'),
    url(r'^renew/$', views.renew, name='renew_all_domain'),
    url(r'^list/$', views.list_cert, name='list_all_domain'),
    url(r'^login/$', views.login, name='login'),
    url(r'', include(router.urls))
]
