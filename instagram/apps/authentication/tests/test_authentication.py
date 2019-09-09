from django.test import TestCase
from django.urls import reverse
from django.contrib.auth.models import User
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from instagram.apps.authentication.utils import account_activation_token


class BaseTest(TestCase):
    def setUp(self):
        self.register_url = reverse('register')
        self.login_url = reverse('login')
        self.user = {
            'name': 'last_name',
            'username': 'username',
            'email': 'email@email.com',
            'password': 'password2!',
            'password2': 'password2!',
        }

        self.user_no_fullname = {
            'name': '',
            'username': 'username',
            'email': 'email@email.com',
            'password': 'password2!',
            'password2': 'password2!',
        }
        self.user_no_username = {
            'name': 'last_name',
            'username': '',
            'email': 'email@email.com',
            'password': 'password2!',
            'password2': 'password2!',
        }
        self.user_no_email = {
            'name': 'last_name',
            'username': 'username',
            'email': '',
            'password': 'password2!',
            'password2': 'password2!',
        }
        self.user_no_password = {
            'name': 'last_name',
            'username': 'username',
            'email': 'email@email.com',
            'password': '',
            'password2': 'password2!',
        }

        self.user_no_password2 = {
            'name': 'last_name',
            'username': 'username',
            'email': 'email@email.com',
            'password': 'password2!',
            'password2': '',
        }


class RegistrationTest(BaseTest):
    def test_correct_html_used(self):
        response = self.client.get(self.register_url)
        self.assertTemplateUsed(response, 'auth/registration.html')

    def test_user_can_register(self):
        response = self.client.post(self.register_url, self.user, format='text/html')
        self.assertEqual(response.status_code, 302)

    def test_user_cant_register_with_no_full_name(self):
        response = self.client.post(self.register_url, self.user_no_fullname, format='text/html')
        self.assertEqual(response.status_code, 400)

    def test_user_cant_register_with_no_username(self):
        response = self.client.post(self.register_url, self.user_no_username, format='text/html')
        self.assertEqual(response.status_code, 400)

    def test_user_cant_register_with_no_email(self):
        response = self.client.post(self.register_url, self.user_no_email, format='text/html')
        self.assertEqual(response.status_code, 400)

    def test_user_cant_register_with_no_password(self):
        response = self.client.post(self.register_url, self.user_no_password, format='text/html')
        self.assertEqual(response.status_code, 400)

    def test_user_cant_register_with_un_matching(self):
        response = self.client.post(self.register_url, self.user_no_password2, format='text/html')
        self.assertEqual(response.status_code, 400)

    def test_user_cant_use_used_email(self):
        self.client.post(self.register_url, self.user, format='text/html')
        response2 = self.client.post(self.register_url, self.user, format='text/html')
        self.assertEqual(response2.status_code, 400)


class LoginTest(BaseTest):
    def test_correct_html_used(self):
        response = self.client.get(self.login_url)
        self.assertTemplateUsed(response, 'auth/login.html')

    def test_should_ogin_successfully(self):
        self.client.post(self.register_url, self.user, format='text/html')
        user = User.objects.first()
        user.is_active = True
        user.save()
        response = self.client.post(self.login_url, self.user, format='text/html')

        self.assertEqual(response.status_code, 302)

    def test_should_notlogin_successfully_when_not_verified(self):
        self.client.post(self.register_url, self.user, format='text/html')
        response = self.client.post(self.login_url, self.user, format='text/html')
        self.assertEqual(response.status_code, 401)

    def test_should_notlogin_successfully_when_nopassword(self):
        response = self.client.post(self.login_url, self.user_no_password, format='text/html')
        self.assertEqual(response.status_code, 401)

    def test_should_notlogin_successfully_when_nousername(self):
        response = self.client.post(self.login_url, self.user_no_username, format='text/html')
        self.assertEqual(response.status_code, 401)


class UserVerificationTest(BaseTest):
    def test_correct_user_verifies_correctly(self):
        user = User.objects.create_user('testuser', 'testuser@gmail.com')
        user.set_password('pass1234')
        user.is_active = False
        user.save()
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = account_activation_token.make_token(user)
        res = self.client.get(reverse('activate', kwargs={'uidb64': uid, 'token': token}))
        self.assertEqual(res.status_code, 302)
        self.assertTrue(User.objects.get(email='testuser@gmail.com').is_active)

    def test_verification_fails_with(self):
        res = self.client.get(reverse('activate', kwargs={'uidb64': 'uid', 'token': 'token'}))
        self.assertEqual(res.status_code, 401)


class ProfileTest(BaseTest):
    def test_unauthenticated_user_does_not_see_profile(self):
        res=self.client.get(reverse('home'))
        self.assertEqual(res.status_code,302)