import jwt

from datetime import datetime, timedelta

from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

from django.db import models

from test_project.settings import SECRET_KEY

class UserManager(BaseUserManager):

    def create_user(self, username, login, email, password=None):
        if username is None:
            raise TypeError('Users must have a username.')

        if login is None:
            raise TypeError('Users must have a login.')
        
        if email is None:
            raise TypeError('Users must have an email address.')

        user = self.model(username=username, login=login, email=self.normalize_email(email))
        user.set_password(password)
        user.save()

        return user

    def create_superuser(self, username, login, email, password):
        if password is None:
            raise TypeError('Superuser must have a password')

        user = self.create_user(username, login, email, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()

        return user

class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(db_index=True, max_length=255, verbose_name='ФИО')
    login = models.CharField(db_index=True, max_length=255, unique=True, verbose_name='Логин')
    email = models.EmailField(db_index=True, unique=True, verbose_name='Email')
    is_staff = models.BooleanField(default=False)
    creation_date = models.DateTimeField(auto_now_add=True)
    updating_date = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'login']

    objects = UserManager()

    def __str__(self):
        return self.email
    
    @property
    def token(self):
        return self._generate_jwt_token()

    def get_full_name(self):
        return self.username
    
    def get_short_name(self):
        return self.username

    def _generate_jwt_token(self):
        dt = datetime.now() + timedelta(days=1)

        token = jwt.encode({
            'id': self.pk,
            'exp': dt.utcfromtimestamp(dt.timestamp())
        }, settings.SECRET_KEY, algorithm='HS256')

        return token