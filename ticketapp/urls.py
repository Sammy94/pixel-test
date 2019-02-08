"""ticketapp URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.conf.urls import url
from django.contrib import admin
from brandapp import views as myapp_views
from django.conf import settings
from django.conf.urls.static import static
from django.conf.urls import include

#get_template
urlpatterns = [
    path('admin/', admin.site.urls),
    url(r'^check/', myapp_views.check),
    url(r'^get_template/', myapp_views.get_template),
    url(r'^temp/', myapp_views.email_temp),
    url(r'^add-template/', myapp_views.add_temp),
    url(r'^view-template', myapp_views.view_template,name='view_template'),
    url(r'^admin-inbox/', myapp_views.ainbox),
    url(r'^admin-inbox-detail', myapp_views.ainbox_d),
    #url(r'^admin-inbox-detail/(?P<init>\w+)$', myapp_views.ainbox_d),
    url(r'^registration/', myapp_views.register),
    url(r'^login/', myapp_views.signin),
    url(r'^dashboard/', myapp_views.dashboard),
    url(r'^verify.dll', myapp_views.verify),
    url(r'^logout', myapp_views.logout_view),
    url(r'^inbox',myapp_views.inbox),
    url(r'^add-ticket',myapp_views.addTicket),
    url(r'^bugbox_hacker/(?P<init>\w+)$',myapp_views.hinbox_d),
    url(r'^markdownx/', include('markdownx.urls')),
    url(r'^image_load/$', myapp_views.image_load, name='image_load'),

    


]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
