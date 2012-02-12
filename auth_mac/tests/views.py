from django.http import HttpResponse

def unattainable_resource(request):
  "Always asks for authorisation."
  response = HttpResponse(status=401)
  response['WWW-Authenticate'] =  'MAC'
  return response