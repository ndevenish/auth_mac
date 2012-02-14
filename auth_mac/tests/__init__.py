"""
This module tests the auth_mac package
"""

from django.test import TestCase
from django.test.client import Client
from django.contrib.auth.models import User
from auth_mac.models import Credentials
import datetime
import hmac, hashlib, base64
import unittest
from auth_mac.tools import Signature

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
  urls = "auth_mac.tests.urls"

  def setUp(self):
    # Create a user to authorise with
    self.user = User.objects.create_user("testuser", "test@test.com")
    self.user.save()
    # And, create a MAC access credentials for this user
    self.rfc_credentials = Credentials(user=self.user, identifier="h480djs93hd8", key="489dks293j39")
    
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
    expired = Credentials(user=self.user, expiry=datetime.datetime.min, identifier="h480djs93hd8", key="489dks293j39")
    expired.save()
    s = Signature(expired, method="GET", port=80, host="example.com", uri="protected_resource")
    c = Client()
    response = c.get("/protected_resource", HTTP_AUTHORIZATION=s.get_header())
    self.assertEqual(response.status_code, 401)
    self.assertIn("EXPIRED".upper(), response["WWW-Authenticate"].upper())

