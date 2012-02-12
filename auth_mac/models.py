from django.db import models
from django.contrib.auth.models import User

class Credentials(models.Model):
  "Keeps track of issued MAC credentials"
  user = models.ForeignKey(User)
  expiry = models.DateTimeField("Expires On")
  identifier = models.CharField("MAC Key Identifier", max_length=16, null=True, blank=True)
  key = models.CharField("MAC Key", max_length=16, null=True, blank=True)

class Nonce(models.Model):
  """Keeps track of any NONCE combinations that we have used"""
  nonce = models.CharField("NONCE", max_length=16, null=True, blank=True)
  timestamp = models.DateTimeField("Timestamp", auto_now_add=True)
  credentials = models.ForeignKey(Credentials)