from django.test import TestCase
from django.urls import reverse


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

    def test_posts_correct_to_login(self):
        response = self.client.post(self.login_url)
        self.assertEqual(response.status_code, 200)
