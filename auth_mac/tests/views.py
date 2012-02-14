from django.http import HttpResponse

from auth_mac.decorators import require_credentials, read_credentials

def unattainable_resource(request):
  "Always asks for authorisation."
  response = HttpResponse(status=401)
  response['WWW-Authenticate'] =  'MAC'
  return response

@require_credentials
def protected_resource(request):
  "Requires Authorisation"
  if request.user.is_anonymous():
    # Something went very wrong if this is the case
    return HttpResponse(status=500)
  return HttpResponse(request.user.username)

@read_credentials
def optional_resource(request):
  "An optional access resource"
  if request.user.is_anonymous():
    return HttpResponse("AnonymousUser")
  
  return HttpResponse(request.user.username)