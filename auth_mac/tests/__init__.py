"""
This file demonstrates writing tests using the unittest module. These will pass
when you run "manage.py test".

Replace this with more appropriate tests for your application.
"""

from django.test import TestCase
from django.test.client import Client


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
    
class Test_Authorisation(TestCase):
  urls = "auth_mac.tests.urls"

  def setUp(self):
    "Initialise the access keys"