MAC Authorisation Module for Django
===================================

:Description: A basic implementation of the RFC draft oauth-v2-http-mac-01__ for Django
:Author:      Nicholas Devenish

.. __: http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-01

Overview
--------

This package implements the current draft of the OAuth-2-related MAC authorisation protocol. This is designed to allow cryptographically reliable requests to be made over a connection that is susceptible to interception. It is based on a shared "secret" which is used to calculate a cryptographic signature at both client and resource server to verify that the request was authentic.

This implementation very simply allows a django view to require that this authentication method be used, or to optionally use the authentication information to determine the user of the request.

Features
--------
These are the features and features of the protocol that this package provides:

* Unique nonce/timestamp/client ID checking; this prevents the possibility of replay attacks (though, see `Limitations`_)
* Uses the hmac-sha-1 algorithm
* partial `ext` header support
* Uses existing Django User framework
* Allows optional usage of credentials
* Authentication errors are communicated back in the WWW-Authentication error parameter

Usage
-----

After adding ``auth_mac`` to your project's settings, and syncing your db, you can create a new set of Credentials through the admin interface, or by instantiating the ``Credentials`` object with an associated user::

  from auth_mac import Credentials
  new_auth = Credentials(user=some_user)
  new_auth.save()

The credentials object will by default be instantiated with a random identifier and secret key, and will have an expiry date set to a day in the future. All of these can be overridden by setting the ``identifier``, ``key`` and ``expiry`` model fields.

When a request is made, you can ensure that the client has authenticated properly by using one of two decorators. The first decorator, **require_credentials**, returns a 401 Unauthorized response if the authentication fails::

  from django.http import HttpResponse
  from auth_mac.decorators import require_credentials

  @require_credentials
  def some_protected_view(request):
    return HttpResponse("This view only runs when authorised!")

And the second decorator, **read_credentials**, allows access even without credentials, but passing credentials will override the ``HttpRequest``'s user property to the authorised user::

  from django.http import HttpResponse
  from auth_mac.decorators import read_credentials

  @read_credentials
  def some_optionally_protected_view(request):
    return HttpResponse("This view can accept Anonymous Users!")

In this second case, if the user is accessing through some other authorisation method i.e. signed in via a session cookie, the credential information (if passed) will overwrite the previous login information.

Limitations
-----------

This is only a very basic implementation of the protocol. Specifically, it does not provide:

* Any way to distribute the secret information. You could do this via an OAuth2 implementation, or manual distribution of the keys. This is because the current design intent is only to provide REST access to a couple of authorised personal clients.
* nonce expiry. At this point in time, nonce values have to be kept indefinitely. Some of the timestamp infrastructure is in place, but until it is completed it is unsafe to remove nonces.
* `hmac-sha-256` is not yet supported
* No rate limitation for protection against flooded requests
* The `ext` parameter is used in calculating the base string, but is not currently handled or tested properly.
* Timestamp verification (including saving of the client offset) is not currently limited. This will be configurable in the future.