from django.urls import path
from . import views

urlpatterns=[
    path('',views.Index),
    path('register',views.RegistrationView.as_view(),name='register')
    ]