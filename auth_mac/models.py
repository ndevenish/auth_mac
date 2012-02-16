from django.db import models
from django.contrib.auth.models import User
import datetime
from auth_mac.utils import random_string, to_utc, utcnow as current_utc_time

def default_expiry_time():
  "The default credential expiry time"
  return current_utc_time() + datetime.timedelta(days=1)

# def current_utc_time():
#   "The current time in UTC"
#   # return to_utc(datetime.datetime.utcnow())
#   return utcnow()

class Credentials(models.Model):
  "Keeps track of issued MAC credentials"
  user = models.ForeignKey(User)
  expiry = models.DateTimeField("Expires On", default=default_expiry_time)
  identifier = models.CharField("MAC Key Identifier", max_length=16, default=random_string)
  key = models.CharField("MAC Key", max_length=16, default=random_string)
  clock_offset = models.IntegerField("Clock Offset", null=True, blank=True)

  def __unicode__(self):
    return u"{0}:{1}".format(self.identifier, self.key)
  
  @property
  def expired(self):
    """Returns whether or not the credentials have expired"""
    if self.expiry < current_utc_time():
      return True
    return False
  
class Nonce(models.Model):
  """Keeps track of any NONCE combinations that we have used"""
  nonce = models.CharField("NONCE", max_length=16, null=True, blank=True)
  timestamp = models.DateTimeField("Timestamp", default=current_utc_time)
  credentials = models.ForeignKey(Credentials)

  def save(self, *args, **kwargs):
    "Reset the timestamp, then save"
    self.timestamp = self.timestamp.replace(microsecond=0)
    super(Nonce, self).save(*args, **kwargs)
  
  def __unicode__(self):
    timestamp = self.timestamp - datetime.datetime(1970,1,1)
    timestamp = timestamp.days * 24 * 3600 + timestamp.seconds
    return u"[{0}/{1}/{2}]".format(self.nonce, timestamp, self.credentials.identifier)