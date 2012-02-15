from functools import wraps
from django.contrib.auth.models import AnonymousUser
from django.http import HttpResponse

from auth_mac.models import Nonce, Credentials
from auth_mac.tools import Validator

def require_credentials(f):
  @wraps(f)
  def wrapper(request, *args, **kwargs):
    """pull the credentials out of the request, and verify them"""
    if not request.META.has_key("HTTP_AUTHORIZATION"):
      response = HttpResponse(status=401)
      response['WWW-Authenticate'] =  'MAC'
      return response
    # Build the validation object
    authstr = request.META["HTTP_AUTHORIZATION"]
    v = Validator(authstr, request)
    if not v.validate():
      response = HttpResponse(status=401)
      if v.error:
        response['WWW-Authenticate'] =  'MAC error="{0}"'.format(v.error)
      else:
        response['WWW-Authenticate'] =  'MAC'
      if v.errorBody:
        response.content = v.errorBody
      return response
    # It validated, use the user
    request.user = v.user

    return f(request, *args, **kwargs)
  return wrapper

def read_credentials(f):
  @wraps(f)
  def wrapper(request, *args, **kwargs):
    """pull the credentials out of the request, and use them if valid"""
    if request.META.has_key("HTTP_AUTHORIZATION"):
      authstr = request.META["HTTP_AUTHORIZATION"]
      v = Validator(authstr, request)
      if v.validate():
        request.user = v.user
    # Now, call the wrapped function regardless
    return f(request, *args, **kwargs)
  return wrapper