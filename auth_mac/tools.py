
import datetime
import hmac, hashlib, base64

def _build_authheader(method, data):
  datastr = ", ".join(['{0}="{1}"'.format(x, y) for x, y in data.iteritems()])
  return "{0} {1}".format(method, datastr)

class Signature(object):
  "A class to ease the creation of MAC signatures"
  MAC = None

  def __init__(self, credentials, host="example.com", port=80):
    self.MAC = credentials
    self.host = host
    self.port = port
    self.ext = ""
  
  def get_timestamp(self):
    timestamp = datetime.datetime.utcnow() - datetime.datetime(1970,1,1)
    return timestamp.days * 24 * 3600 + timestamp.seconds
  
  def get_nonce(self):
    return User.objects.make_random_password(8)

  def sign_request(self, uri, method="GET", timestamp=None, nonce=None):
    """Signs a request to a specified URI and returns the signature"""
    if not timestamp:
      self.timestamp = self.get_timestamp()
      timestamp = self.timestamp
    if not nonce:
      self.nonce = self.get_nonce()
      nonce = self.nonce
    self.nonce = nonce
    self.timestamp = timestamp
    method = method.upper()
    if not method in ("GET", "POST"):
      raise RuntimeError("HTTP Method {0} not supported!".format(method))
    
    data = [timestamp, nonce, method, uri, self.host, self.port, self.ext]
    data = [str(x) for x in data]
    self.base_string = "\n".join(data) + "\n"
    # print repr(basestr)
    # print "Signing with key '{0}'".format(self.MAC.key)
    hm = hmac.new(self.MAC.key, self.base_string, hashlib.sha1)
    self.signature = base64.b64encode(hm.digest())
    # print self.signature
    return self.signature
  
  def get_header(self):
    # {"id": "h480djs93hd8","ts": "1336363200","nonce":"dj83hs9s","mac":"bhCQXTVyfj5cmA9uKkPFx1zeOXM="}
    data = {"id": self.MAC.identifier, 
            "ts": self.timestamp,
            "nonce": self.nonce,
            "mac": self.signature }
    return _build_authheader("MAC", data)
