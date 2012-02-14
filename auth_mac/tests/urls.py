# Try the django-1.4 location first
try:
    from django.conf.urls import patterns, include, url
except ImportError:
    from django.conf.urls.defaults import patterns, include, url


# Build the URL patterns for testing the MAC auth
urlpatterns = patterns('auth_mac.tests.views',
    # url(r'^$',         'plain', name='plain'),
    # url(r'^optional$', 'optional_auth', name="Optional")
    url(r'unattainable_resource$', 'unattainable_resource'),
    url(r'protected_resource$', 'protected_resource'),
    url(r'optional_resource$', 'optional_resource'),
)
