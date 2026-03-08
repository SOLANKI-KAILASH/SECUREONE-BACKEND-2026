from django.urls import path
from .views import *
 
urlpatterns = [
    path("breach-check/", password_breach_check),
    path("domain-info/", domain_info),
    path("ssl-check/", ssl_check),
     path("report/", add_report),   # note trailing slash
    path("reports/", get_reports),
]