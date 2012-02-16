import logging
from django.utils.log import NullHandler

logging.getLogger('auth_mac').addHandler(NullHandler())