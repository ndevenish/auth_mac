
import datetime
from django.conf import settings
import random

# Use the django 1.4 timezone supoprt if possible
try:
  import django.utils.timezone as timezone
except:
  timezone = None

def to_utc(naive_datetime):
  "Converts a naive to non-naive datetime.... if TZ support is enabled"
  # Check we have timezone support
  if not timezone or not hasattr(settings, "USE_TZ"):
    return naive_datetime
  if not settings.USE_TZ:
    return naive_datetime
  # We have timezone support, and it is on
  return naive_datetime.replace(tzinfo=timezone.utc)

def utcnow():
  "Returns a timezone-aware-appropriate UTC now"
  return to_utc(datetime.datetime.utcnow())

def random_string(length=16):
  random_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890_"
  return "".join(random.sample(random_chars, length))