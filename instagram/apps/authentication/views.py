from django.shortcuts import render, redirect
from django.views.generic import View
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.messages import get_messages


# Create your views here.

def Index(request):
    return render(request, 'index.html')


class RegistrationView(View):
    def get(self, request):
        return render(request, 'auth/registration.html')

    def post(self, request):

        context = {
            'data': request.POST,
            'has_error': False
        }

        username = request.POST.get('username')
        fullname = request.POST.get('name')
        email = request.POST.get('email')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')

        if username == '':
            messages.add_message(request, messages.ERROR, 'username are required')
            context['has_error'] = True
        if email == '':
            messages.add_message(request, messages.ERROR, 'email are required')
            context['has_error'] = True
        if fullname == '':
            messages.add_message(request, messages.ERROR, 'fullname are required')
            context['has_error'] = True
        if (password or password2) == '':
            messages.add_message(request, messages.ERROR, 'Passwords are required')
            context['has_error'] = True
        if password != password2:
            messages.add_message(request, messages.ERROR, 'Passwords do not match')
            context['has_error'] = True
        if User.objects.filter(email=email).exists():
            messages.add_message(request, messages.ERROR, 'email is taken,chose another one')
            context['has_error'] = True
        if User.objects.filter(username=username).exists():
            messages.add_message(request, messages.ERROR, 'username is taken,chose another one')
            context['has_error'] = True
        if context['has_error']:
            return render(request, 'auth/registration.html', context, status=400)

        new_user = User.objects.create_user(username=username, email=email)
        new_user.set_password(password)
        new_user.first_name = fullname
        new_user.last_name = 'test'
        new_user.save()

        messages.add_message(request, messages.SUCCESS, 'Account created successfully,please visit your Email to '
                                                        'verify your Account')
        return redirect('login')


class LoginView(View):
    def get(self, request):
        return render(request, 'auth/login.html')


    def post(self, request):

        return render(request, 'auth/login.html')
