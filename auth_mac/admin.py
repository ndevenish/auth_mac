from auth_mac.models import Credentials, Nonce
from django.contrib import admin


class CredentialsAdmin(admin.ModelAdmin):
  list_display = ['user', 'expiry', 'identifier', 'key', 'clock_offset' ]
  # date_hierarchy = 'start'
  ordering = ('user',)
  # form = TokenForm

class NonceAdmin(admin.ModelAdmin):
  list_display = ['timestamp', 'credentials', 'nonce']

admin.site.register(Credentials, CredentialsAdmin)
admin.site.register(Nonce, NonceAdmin)
