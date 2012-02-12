from django.db import models
from django.contrib.auth.models import User
import datetime

def default_expiry_time():
  return datetime.datetime.now() + datetime.timedelta(days=1)

def random_string():
  return User.objects.make_random_password(16)

class Credentials(models.Model):
  "Keeps track of issued MAC credentials"
  user = models.ForeignKey(User)
  expiry = models.DateTimeField("Expires On", default=default_expiry_time)
  identifier = models.CharField("MAC Key Identifier", max_length=16, default=random_string)
  key = models.CharField("MAC Key", max_length=16, default=random_string)

  def __unicode__(self):
    return u"{0}:{1}".format(self.identifier, self.key)
  
class Nonce(models.Model):
  """Keeps track of any NONCE combinations that we have used"""
  nonce = models.CharField("NONCE", max_length=16, null=True, blank=True)
  timestamp = models.DateTimeField("Timestamp", auto_now_add=True)
  credentials = models.ForeignKey(Credentials)