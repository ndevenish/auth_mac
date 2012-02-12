from functools import wraps
from django.contrib.auth.models import AnonymousUser
from django.http import HttpResponse

from auth_mac.models import Nonce, Credentials