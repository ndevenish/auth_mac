"""
This file demonstrates writing tests using the unittest module. These will pass
when you run "manage.py test".

Replace this with more appropriate tests for your application.
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
    # self.credentials = Credentials(user=user, identifier="h480djs93hd8", key="489dks293j39")
    self.rfc_credentials = rfc_creds = Credentials(user=self.user, identifier="h480djs93hd8", key="489dks293j39")
  
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


class TestRequest(TestCase):
  urls = "auth_mac.tests.urls"
  def test_dumping(self):
    c = Client()
    # print c.get("/dump_request", HTTP_AUTHORIZATION=)
    data = {"id": "h480djs93hd8","ts": "1336363200","nonce":"dj83hs9s","mac":"bhCQXTVyfj5cmA9uKkPFx1zeOXM="}
    # print build_authheader("MAC", data)