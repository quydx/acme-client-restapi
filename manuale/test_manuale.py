"""
The command line interface.
"""
import json
import argparse
import logging
import sys
import os
import time 
from pprint import pprint
from manuale.account import Account
from manuale.account import deserialize as deserialize_account
import authorize 
from manuale.issue import issue
from manuale.info import info
from manuale.register import register
from manuale.revoke import revoke
from manuale.errors import ManualeError
from manuale.acme import Acme
import manuale

logger = logging.getLogger(__name__)

REDIS_SERVER='192.168.158.86'
REDIS_PORT=6379
REDIS_DB=0

LETS_ENCRYPT_PRODUCTION = "https://acme-v01.api.letsencrypt.org/"
DEFAULT_ACCOUNT_PATH = 'account.json'
DEFAULT_CERT_KEY_SIZE = 2048

def load_account(path):
    # Show a more descriptive message if the file doesn't exist.
    if not os.path.exists(path):
        logger.error("Couldn't find an account file at {}.".format(path))
        logger.error("Are you in the right directory? Did you register yet?")
        logger.error("Run 'manuale -h' for instructions.")
        raise ManualeError()

    try:
        with open(path, 'rb') as f:
            return deserialize_account(f.read())
    except (ValueError, IOError) as e:
        logger.error("Couldn't read account file. Aborting.")
        raise ManualeError(e)




account = load_account('account.json')

print(account.key)
# sys.exit()

acme = Acme(LETS_ENCRYPT_PRODUCTION, account)
print(acme.url)

authorize.authorize(LETS_ENCRYPT_PRODUCTION, account, ['quydxtu11.tk'], 'dns')

time.sleep(60)

# rds = redis.StrictRedis(host=REDIS_SERVER, port=REDIS_PORT, db=REDIS_DB)
# authz = rds.hget('xx12', 'authz')
# authorize.verify_auth(account.key, authz)
