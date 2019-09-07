from django.shortcuts import render
from django.views.generic import View


# Create your views here.

def Index(request):
    return render(request, 'index.html')


class RegistrationView(View):
    def get(self, request):
        return render(request, 'auth/registration.html')

    def post(self, request):
        return render(request, 'auth/registration.html')
