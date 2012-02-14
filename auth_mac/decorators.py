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

# def extract(d, keys):
#   "Extract a subset of a dictionary"
#   return dict((k, d[k]) for k in keys if k in d)

# def read_api_token(f):
#   @wraps(f)
#   def wrapper(request, *args, **kwargs):
#     # If we have an API request, then prefer this auth

#     # Extract the API information from the request
#     authkeys = extract(request.REQUEST, ["client_key", "access_key", "nonce", "signature"])
#     user = TokenAuthorisation().authenticate(**authkeys)
#     # Replace the user if this worked, otherwise resume with the default
#     if user:
#       request.user = user
    
#     return f(request, *args, **kwargs)
#   return wrapper

# def require_api_token(f):
#   @wraps(f)
#   def wrapper(request, *args, **kwargs):
#     # Extract the API information from the request
#     authkeys = extract(request.REQUEST, ["client_key", "access_key", "nonce", "signature"])
#     ta = TokenAuthorisation()
#     user = ta.authenticate(**authkeys)
#     if user is None:
#       response = HttpResponse("Invalid API Token Authorisation:\n{0}".format(ta.errormessage),
#                               status=401, content_type="text/plain")
#       return response

#     request.user = user
#     return f(request, *args, **kwargs)
#   return wrapper