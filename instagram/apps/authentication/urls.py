from django.urls import path,include
from . import views

urlpatterns = [
    path('register', views.RegistrationView.as_view(), name='register'),
    path('login', views.LoginView.as_view(), name='login'),
    path('activate/<uidb64>/<token>', views.VerificationView.as_view(), name='activate'),
    path('profile',views.ProfileView.as_view(),name='home'),
    path('social-auth/', include('social_django.urls', namespace="social")),
]
