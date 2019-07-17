from cryptography import x509
import logging
import os,sys
import pkg_resources
import re
import json

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import josepy as jose
import OpenSSL

import six

from acme import client
from acme import messages
from acme import crypto_util, challenges
from acme.client import ClientNetwork, ClientV2


with open("cert.tmp", "rb") as pem_data:
        pem_data = pem_data.read()
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        print pem_data
        print cert.not_valid_after
