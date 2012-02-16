#from distutils.core import setup
from setuptools import setup

setup(
    name='django-auth_mac',
    version='0.1.2',
    description="Basic Django implementation of the draft RFC ietf-oauth-v2-http-mac-01",
    author='Nicholas Devenish',
    author_email='n.devenish@gmail.com',
    packages=['auth_mac', 'auth_mac.tests'],
    license=open('LICENSE.txt').read(),
    long_description=open('README.rst').read(),
    url='https://github.com/ndevenish/auth_mac',
    keywords = ['django', 'authorization', 'MAC'],
    classifiers = [
      "Programming Language :: Python",
      "Programming Language :: Python :: 2.6",
      "Programming Language :: Python :: 2.7",
      "License :: OSI Approved :: MIT License",
      "Framework :: Django",
      "Operating System :: OS Independent",
      "Intended Audience :: Developers",
      "Topic :: Internet :: WWW/HTTP :: WSGI :: Middleware",
      "Development Status :: 2 - Pre-Alpha",
      "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    install_requires=['Django >= 1.3'],
    zip_safe=False,
)