"""
This module tests the auth_mac package
"""

from django.test import TestCase
from django.test.client import Client
from django.contrib.auth.models import User
from auth_mac.models import Credentials, Nonce
import datetime
import hmac, hashlib, base64
import unittest
from auth_mac.tools import Signature, to_utc

class Test_NoAuthorisation(TestCase):
  urls = "auth_mac.tests.urls"
  def test_access_restricted(self):
    "Tests accessing restricted functions without authentication"
    c = Client()
    response = c.get("/unattainable_resource")
    self.assertEqual(response.status_code, 401)
    self.assertEqual(response['WWW-Authenticate'], "MAC")
    
    response = c.get("/protected_resource")
    self.assertEqual(response.status_code, 401)
    self.assertEqual(response['WWW-Authenticate'], "MAC")



class Test_Signatures(TestCase):
  urls = "auth_mac.tests.urls"

  def setUp(self):
    # Create a user to authorise with
    self.user = User.objects.create_user("testuser", "test@test.com")
    self.user.save()
    # And, create a MAC access credentials for this user
    self.rfc_credentials = Credentials(user=self.user, identifier="h480djs93hd8", key="489dks293j39")
  
  @unittest.expectedFailure
  def test_credential_object(self):
    """Test the credentials object using the IETF Draft values.
    See: http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-01 """
        
    ms = Signature(self.rfc_credentials, host="example.com", port=80, method="GET")
    ms.sign_request(uri="/resource/1?b=1&a=2", timestamp="1336363200", nonce="dj83hs9s")
    # Validate that we calculated the base string correctly
    example_bs = "1336363200\ndj83hs9s\nGET\n/resource/1?b=1&a=2\nexample.com\n80\n\n"
    self.assertEqual(ms.base_string, example_bs)
    self.assertEqual(ms.signature, "bhCQXTVyfj5cmA9uKkPFx1zeOXM=")

  def test_possible_erroneous_credentials(self):
    "Test that we don't stray from our self-calculated output"
    # Same as above test, but with a different signature
    ms = Signature(self.rfc_credentials, host="example.com", port=80, method="GET")
    ms.sign_request(uri="/resource/1?b=1&a=2", timestamp="1336363200", nonce="dj83hs9s")
    example_bs = "1336363200\ndj83hs9s\nGET\n/resource/1?b=1&a=2\nexample.com\n80\n\n"
    self.assertEqual(ms.base_string, example_bs)
    self.assertEqual(ms.signature, "6T3zZzy2Emppni6bzL7kdRxUWL4=")
  
  def test_creating_authheader(self):
    "Test the creation of the auth header"
    ms = Signature(self.rfc_credentials, host="example.com", port=80, method="GET")
    ms.update(uri="/resource/1?b=1&a=2", timestamp="1336363200", nonce="dj83hs9s")
    expected_authheader = 'MAC nonce="dj83hs9s", mac="6T3zZzy2Emppni6bzL7kdRxUWL4=", id="h480djs93hd8", ts="1336363200"'
    header = ms.get_header()
    self.assertEqual(expected_authheader, header)

class TestRequest(TestCase):
  "Test the sending of requests and validation against credentials"
  urls = "auth_mac.tests.urls"

  def setUp(self):
    # Create a user to authorise with
    self.user = User.objects.create_user("testuser", "test@test.com")
    self.user.save()
    # And, create a MAC access credentials for this user
    self.rfc_credentials = Credentials(user=self.user, identifier="h480djs93hd8", key="489dks293j39")
    self.rfc_credentials.save()
    
  def test_workingcredentials(self):
    "Tests that we can read a resource with working credentials"
    c = Client()
    ms = Signature(self.rfc_credentials, host="example.com", port=80, method="GET")
    ms.update(uri="/protected_resource")
    c.get("/protected_resource", HTTP_AUTHORIZATION=ms.get_header())
  
  def test_nonmac_credentials(self):
    "Tests that sending a non-mac authentication fails"
    c = Client()
    ms = Signature(self.rfc_credentials, host="example.com", port=80, method="GET")
    ms.update(uri="/protected_resource")
    header = ms.get_header()
    response = c.get("/protected_resource", HTTP_AUTHORIZATION="Basic " + header[4:])
    self.assertEqual(response.status_code, 401)
    # Make sure we don't have an error string
    self.assertEqual(response['WWW-Authenticate'], "MAC")

  def test_refuse_repeats(self):
    "Tests that repeating auth information fails auth"
    c = Client()
    validheader = 'MAC nonce="dj83hs9s", mac="6T3zZzy2Emppni6bzL7kdRxUWL4=", id="h480djs93hd8", ts="1336363200", ext="fsf"'
    for key in ["nonce", "mac", "id", "ts", "ext"]:
      keystr = validheader + ', {0}="rextra"'.format(key)
      response = c.get("/protected_resource", HTTP_AUTHORIZATION=keystr)
      self.assertEqual(response.status_code, 401)
      self.assertIn("Duplicate", response["WWW-Authenticate"])
  
  def test_incomplete_information(self):
    "Test that giving incomplete mac information fails"
    c = Client()
    keystrs = [ 'MAC mac="6T3zZzy2Emppni6bzL7kdRxUWL4=", id="h480djs93hd8", ts="1336363200"',
                'MAC nonce="dj83hs9s", id="h480djs93hd8", ts="1336363200"',
                'MAC nonce="dj83hs9s", mac="6T3zZzy2Emppni6bzL7kdRxUWL4=", ts="1336363200"',
                'MAC nonce="dj83hs9s", mac="6T3zZzy2Emppni6bzL7kdRxUWL4=", id="h480djs93hd8"']
    for keystr in keystrs:
      response = c.get("/protected_resource", HTTP_AUTHORIZATION=keystr)
      self.assertEqual(response.status_code, 401)
      self.assertIn("Missing", response["WWW-Authenticate"])

  def test_invalid_credentials(self):
    "Test using credentials that are invalid, but signed correctly"
    c = Client()
    class CredShell(object):
      key = "NOTAVALIDKEY"
      identifier = "NOTANIDENTIFIER"
    bad = CredShell()
    # validheader = 'MAC nonce="dj83hss9s", mac="6T3zZzy2Emppni6bzL7kdRxUWL4=", id="h480djs93hd8", ts="1336363200", ext="fsf"'
    s = Signature(bad, method="GET", port=80, host="example.com", uri="protected_resource")
    response = c.get("/protected_resource", HTTP_AUTHORIZATION=s.get_header())
    self.assertEqual(response.status_code, 401)
    self.assertIn("Invalid", response["WWW-Authenticate"])

  def test_expired_credentials(self):
    "Test using credentials that have expired"
    expired_date = to_utc(datetime.datetime.utcnow()) - datetime.timedelta(days=5)    
    expired = Credentials(user=self.user, expiry=expired_date, identifier="hdjs93hd8", key="489dks2939")
    expired.save()
    s = Signature(expired, method="GET", port=80, host="example.com", uri="protected_resource")
    c = Client()
    response = c.get("/protected_resource", HTTP_AUTHORIZATION=s.get_header())
    self.assertEqual(response.status_code, 401)
    self.assertIn("EXPIRED".upper(), response["WWW-Authenticate"].upper())

  def test_header_without_host(self):
    "Tests that signature does not proceed without a valid host value"
    validheader = 'MAC nonce="djd3hs9s", mac="INVALIDSIGNATURE=", id="h480djs93hd8", ts="1336363200"'
    c = Client()
    response = c.get("/protected_resource", HTTP_AUTHORIZATION=validheader)
    self.assertEqual(response.status_code, 401)
    self.assertIn("Host", response["WWW-Authenticate"])    

  def test_invalid_signature(self):
    "Test using a valid credential with an invalid signature"
    validheader = 'MAC nonce="djd3hs9s", mac="INVALIDSIGNATURE=", id="h480djs93hd8", ts="1336363200"'
    c = Client()
    response = c.get("/protected_resource", HTTP_AUTHORIZATION=validheader, HTTP_HOST="example.com")
    self.assertEqual(response.status_code, 401)
    self.assertIn("SIGNATURE".upper(), response["WWW-Authenticate"].upper())
  
  def test_valid_signature(self):
    "Test using a valid credential with a valid signature"
    s = Signature(self.rfc_credentials, method="GET", port=80, host="example.com", uri="/protected_resource")
    header = s.get_header()
    c = Client()
    response = c.get("/protected_resource", HTTP_AUTHORIZATION=header, HTTP_HOST="example.com")
    self.assertEqual(response.status_code, 200)
    self.assertEqual(response.content, "testuser")

class TestUsers(TestCase):
  urls = "auth_mac.tests.urls"

  def setUp(self):
    # Create a user to authorise with
    self.user = User.objects.create_user("testuser", "test@test.com")
    self.user.save()
    # And, create a MAC access credentials for this user
    self.rfc_credentials = Credentials(user=self.user, identifier="h480djs93hd8", key="489dks293j39")
    self.rfc_credentials.save()
  
  def test_anonymousaccess(self):
    "Test the access of an optionally anonymous resource"
    c = Client()
    response = c.get("/optional_resource")
    self.assertEqual(response.status_code, 200)
    self.assertEqual(response.content, "AnonymousUser")
  
  def test_authaccess(self):
    "Test optional authorisation access with user credentials"
    s = Signature(self.rfc_credentials, method="GET", port=80, host="example.com", uri="/optional_resource")
    header = s.get_header()
    c = Client()
    response = c.get("/optional_resource", HTTP_AUTHORIZATION=header, HTTP_HOST="example.com")
    self.assertEqual(response.status_code, 200)
    self.assertEqual(response.content, "testuser")

class TestNonce(TestCase):
  "Tests the nonce-evasion procedures"
  urls = "auth_mac.tests.urls"

  def setUp(self):
    # Create a user to authorise with
    self.user = User.objects.create_user("testuser", "test@test.com")
    self.user.save()
    # And, create a MAC access credentials for this user
    self.rfc_credentials = Credentials(user=self.user, identifier="h480djs93hd8", key="489dks293j39")
    self.rfc_credentials.save()
    self.signature = Signature(self.rfc_credentials, method="GET", port=80, host="example.com", uri="/protected_resource")
    self.timestamp = datetime.datetime.utcnow()
    now = self.timestamp-datetime.datetime(1970,1,1)
    self.timestamp = to_utc(self.timestamp)
    self.now = now.days * 24*3600 + now.seconds
  

  def test_nonceexists(self):
    "Test the failure of a pre-existing nonce"
    nonce = Nonce(nonce="NONCE", timestamp=self.timestamp, credentials=self.rfc_credentials)
    nonce.save()
    self.signature.update(timestamp=self.now, nonce="NONCE")
    c = Client()
    response = c.get("/protected_resource", 
                    HTTP_AUTHORIZATION=self.signature.get_header(), 
                    HTTP_HOST="example.com")
    self.assertEqual(response.status_code, 401)
    self.assertIn("NONCE".upper(), response["WWW-Authenticate"].upper())

  def test_duplicate(self):
    "Test sending the same nonce and timestamp through fails"
    c = Client()
    self.signature.update(nonce="A_NONCE", timestamp=self.now)
    response = c.get("/protected_resource", 
                    HTTP_AUTHORIZATION=self.signature.get_header(), 
                    HTTP_HOST="example.com")
    
    self.assertEqual(response.status_code, 200)
    response = c.get("/protected_resource", 
                    HTTP_AUTHORIZATION=self.signature.get_header(), 
                    HTTP_HOST="example.com")
    self.assertEqual(response.status_code, 401)
    self.assertIn("NONCE".upper(), response["WWW-Authenticate"].upper())

class TestTimestamps(TestCase):
  "Tests the timestamp adjustment and verification facilities"
  urls = "auth_mac.tests.urls"

  def setUp(self):
    # Create a user to authorise with
    self.user = User.objects.create_user("testuser", "test@test.com")
    self.user.save()
    # And, create a MAC access credentials for this user
    self.rfc_credentials = Credentials(user=self.user, identifier="h480djs93hd8", key="489dks293j39")
    self.rfc_credentials.save()
    self.signature = Signature(self.rfc_credentials, method="GET", port=80, host="example.com", uri="/protected_resource")
    self.timestamp = datetime.datetime.utcnow()
    now = self.timestamp-datetime.datetime(1970,1,1)
    self.timestamp = to_utc(self.timestamp)
    self.now = now.days * 24*3600 + now.seconds
  
  def test_offsetregistration(self):
    "Test that using credentials fixes the associated clock offset"
    