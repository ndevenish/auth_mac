
import datetime
import hmac, hashlib, base64
from django.contrib.auth.models import User
from auth_mac.models import Credentials
import re

reHeader = re.compile(r"""(mac|nonce|id|ts|ext)="([^"]+)""")

def _build_authheader(method, data):
  datastr = ", ".join(['{0}="{1}"'.format(x, y) for x, y in data.iteritems()])
  return "{0} {1}".format(method, datastr)

class SignatureError(Exception):
    pass

class Signature(object):
  "A class to ease the creation of MAC signatures"
  MAC = None
  data = {}
  base_string = None
  
  def __init__(self, credentials, **kwargs):
    self.MAC = credentials
    self.update_data_from_dictionary(kwargs)

  def _add_data_item(self, from_dict, name, default=None):
    """Basic inline function to add a key to the self data"""
    if from_dict.has_key(name):
      self.data[name] = from_dict[name]
    else:
      if not self.data.has_key(name):
        self.data[name] = default
  
  def update_data_from_dictionary(self, from_dict):
    "Read all required information out of a dictionary"
    self._add_data_item(from_dict, "method", None)
    self._add_data_item(from_dict, "uri", None)
    self._add_data_item(from_dict, "host", None)
    self._add_data_item(from_dict, "port", None)
    self._add_data_item(from_dict, "ext", "")
    self._add_data_item(from_dict, "timestamp", None)
    self._add_data_item(from_dict, "nonce", None)
    # If we are changing, wipe out the signature and base string
    self.base_string = None
    self.signature = None
  
  def update(self, **kwargs):
    "Update the parameters from a dictionary"
    self.update_data_from_dictionary(kwargs)

  def _get_timestamp(self):
    timestamp = datetime.datetime.utcnow() - datetime.datetime(1970,1,1)
    return timestamp.days * 24 * 3600 + timestamp.seconds
  
  def _get_nonce(self):
    return User.objects.make_random_password(8)

  def validate(self):
    "Validates that we have all the required information"
    if not self.MAC:
      raise SignatureError("Have not been given a MAC credential")
    required_values = {
      "method": "HTTP Request Method",
      "uri": "HTTP Request URI",
      "host": "Destination Host",
      "port": "Destination Port",
    }
    # Check all of these
    for key, errorstring in required_values.iteritems():
      errorstring = "Missing information for signature: {0}".format(errorstring)
      # If we don't have the key, or the key is None
      if not self.data.has_key(key):
        raise SignatureError(errorstring)
      else:
        if not self.data[key]:
          raise SignatureError(errorstring)
    # If the timestamp or nonce are blank, generate them
    if not self.data["nonce"]:
      self.data["nonce"] = self._get_nonce()
    if not self.data["timestamp"]:
      self.data["timestamp"] = self._get_timestamp()
    # Make sure the method is capitalised
    self.data["method"] = self.data["method"].upper()

  def sign_request(self, **kwargs):
    """Signs a request to a specified URI and returns the signature"""
    self.update_data_from_dictionary(kwargs)
    self.validate()
    return calculate_signature()
  
  def calculate_signature(self):
    "Calculates the signature given internal data"
    
    # What order do we use for calculations?
    data_vars = ["timestamp", "nonce", "method", "uri", "host", "port", "ext"]
    data = [str(self.data[x]) for x in data_vars]
    self.base_string = "\n".join(data) + "\n"
    # print "Signing with key '{0}'".format(self.MAC.key)
    hm = hmac.new(self.MAC.key, self.base_string, hashlib.sha1)
    self.signature = base64.b64encode(hm.digest())
    return self.signature
  
  def get_header(self, **kwargs):
    "Return the HTTP Authorization header for the set IDs"
    self.update_data_from_dictionary(kwargs)
    self.validate()
    data = {"id": self.MAC.identifier, 
            "ts": self.data["timestamp"],
            "nonce": self.data["nonce"],
            "mac": self.sign_request() }
    # Include the optional ext field
    if self.data["ext"]:
      data["ext"] = self.data["ext"]
    return _build_authheader("MAC", data)

class Validator(object):
  """Validates the mac credentials passed in from an HTTP HEADER"""
  error = None

  def __init__(self, Authorization):
    self.authstring = Authorization
  
  def validate_header(self):
    "Validates that the header string is well formed"
    if not self.authstring.startswith("MAC "):
      # We have not tried to authenticate with MAC credentials
      return False
    # Split the string into key/value pairs
    results = reHeader.findall(self.authstring)
    # Verify that none are repeated
    for key, value in results:
      # Check they are all identified
      if not key in ("mac", "nonce", "ext", "id", "ts"):
        self.error = "Unidentified param"
        return False
      # Find all supplied keys with this keyname
      allkeys = [x for x, y in results if x == key]
      if len(allkeys) > 1:
        self.error = "Duplicate key '{0}'".format(key)
        return False
    # Verify that none are missing
    data = dict(results)
    if not all(data.has_key(x) for x in ("mac", "nonce", "id", "ts")):
      self.error = "Missing authorisation information"
      return False
    self.data = data
    return True

  def validate_credentials(self):
    "Validates that the credentials are valid"
    try:
      credentials = Credentials.objects.get(identifier=self.data["id"])
    except Credentials.DoesNotExist:
      self.error = "Invalid MAC credentials"
      return False
    
    # Check that it hasn't expired
    if credentials.expired:
      self.error = "MAC credentials expired"
      return False
    
    return True
  
  def validate_nonce(self):
    "Validates that the nonce is not a repeat"
    return True
  
  def validate_signature(self):
    "Validates that the signature is good"
    # Find the credentials for this ID
    return True
  
  def validate(self):
    "Validates that everything is well formed and signed correctly"
    # Validate the forming of the signature, this will fill _data
    if not self.validate_header():
      return False
    # Validate that this nonce is not out of date
    if not self.validate_nonce():
      return False
    # Validate that the credentials are good and current
    if not self.validate_credentials():
      return False
    # Now, validate the cryptographic signature..
    if not self.validate_signature():
      return False