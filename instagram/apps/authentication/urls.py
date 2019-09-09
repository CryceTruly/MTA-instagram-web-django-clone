from django.urls import path,include
from . import views

from django.contrib.auth.decorators import login_required
urlpatterns = [
    path('register', views.RegistrationView.as_view(), name='register'),
    path('login', views.LoginView.as_view(), name='login'),
    path('logout', views.LogoutView.as_view(), name='logout'),
    path('activate/<uidb64>/<token>', views.VerificationView.as_view(), name='activate'),
    path('',login_required(views.ProfileView.as_view()) ,name='home'),
    path('request-reset', views.RequestResetLinkView.as_view(), name='reset-password'),
    path('change-password/<uidb64>/<token>', views.CompletePasswordChangeView.as_view(), name='change-password'),
    path('social-auth/', include('social_django.urls', namespace="social")),
]
