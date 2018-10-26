"""
The domain authorization command.
"""
import copy
import sys
import json
import logging
import time
import hashlib
import os
import redis
import requests

from urllib.parse import urljoin, urlparse
from pprint import pprint
from manuale.acme import Acme
from manuale.crypto import generate_jwk_thumbprint, jose_b64
from manuale.errors import ManualeError, AcmeError
from manuale.helpers import confirm
from manuale.crypto import generate_header, sign_request
logger = logging.getLogger(__name__)

__version__ = '1.0'

DEFAULT_HEADERS = {
    'User-Agent': "manuale {} (https://github.com/veeti/manuale)".format(__version__),
}

LETS_ENCRYPT_PRODUCTION = "https://acme-v01.api.letsencrypt.org/"

DEFAULT_ACCOUNT_PATH = 'account.json'
DEFAULT_CERT_KEY_SIZE = 2048


def get_challenge(auth, auth_type):
    try:
        return [ch for ch in auth.get('challenges', []) if ch.get('type') == auth_type][0]
    except IndexError:
        raise ManualeError("The server didn't return a '{}' challenge.".format(auth_type))

def retrieve_verification(acme, domain, auth, method):
    while True:
        print("{}: waiting for verification. Checking in 5 seconds.".format(domain))
        time.sleep(5)

        response = acme.get_authorization(auth['uri'])
        status = response.get('status')
        if status == 'valid':
            print("{}: OK! Authorization lasts until {}.".format(domain, response.get('expires', '(not provided)')))
            return True
        elif status != 'pending':
            # Failed, dig up details
            error_type, error_reason = "unknown", "N/A"
            try:
                challenge = get_challenge(response, method)
                error_type = challenge.get('error').get('type')
                error_reason = challenge.get('error').get('detail')
            except (ManualeError, ValueError, IndexError, AttributeError, TypeError):
                pass

            print("{}: {} ({})".format(domain, error_reason, error_type))
            return False

def authorize(server, account, domains, method='dns'):
    method = method + '-01'
    acme = Acme(server, account)
    thumbprint = generate_jwk_thumbprint(account.key)
    # Get pending authorizations for each domain
    authz = {}
    for domain in domains:
        print('authorize for domain {}'.format(domain))
        print("Requesting challenge for {}.".format(domain))
        created = acme.new_authorization(domain)
        # pprint(created)
        # sys.exit()
        auth = created.contents
        auth['uri'] = created.uri

        # Check if domain is already authorized
        if auth.get('status') == 'valid':
            print("{} is already authorized until {}.".format(domain, auth.get('expires', '(unknown)')))
            continue

        # Find the challenge and calculate values
        auth['challenge'] = get_challenge(auth, method)
        auth['key_authorization'] = "{}.{}".format(auth['challenge'].get('token'), thumbprint)
        digest = hashlib.sha256()
        digest.update(auth['key_authorization'].encode('ascii'))
        auth['txt_record'] = jose_b64(digest.digest())
        authz[domain] = auth

    # Quit if nothing to authorize
    if not authz:
        print("")
        print("All domains are already authorized, exiting.")
        return

    print("")
    print("DNS verification required. Make sure these TXT records are in place:")
    print("")
    for domain, auth in authz.items():
        print("  _acme-challenge.{}.  IN TXT  \"{}\"".format(domain, auth['txt_record']))
    


def verify(acme, authz, method='dns-01'):
    # Validate challenges
    done, failed = set(), set()
    for domain, auth in authz.items():
        logger.info("")
        challenge = auth['challenge']
        acme.validate_authorization(challenge['uri'], method, auth['key_authorization'])
        if retrieve_verification(acme, domain, auth, method):
            done.add(domain)
        else:
            failed.add(domain)



def path(path):
    # Make sure path is relative
    if path.startswith('http'):
        path = urlparse(path).path
    return urljoin(LETS_ENCRYPT_PRODUCTION, path)

def get(path, headers=None):
    _headers = DEFAULT_HEADERS.copy()
    if headers:
        _headers.update(headers)
    return requests.get(path(path), headers=_headers)

def get_nonce():
    """
    Gets a new nonce.
    """
    return get('/directory').headers.get('Replay-Nonce')

def get_headers(account_key):
    """
    Builds a new pair of headers for signed requests.
    """
    header = generate_header(account_key)
    protected_header = copy.deepcopy(header)
    protected_header['nonce'] = get_nonce()
    return header, protected_header

def post(account_key, path, body, headers=None):
    _headers = DEFAULT_HEADERS.copy()
    _headers['Content-Type'] = 'application/json'
    if headers:
        _headers.update(headers)

    header, protected = get_headers(account_key)
    body = sign_request(account_key, header, protected, body)

    return requests.post(path(path), data=body, headers=_headers)


def verify_auth(account_key, authz, method='dns-01'):
    # done, failed = set(), set()
    for domain, auth in authz.items():
        logger.info("")
        challenge = auth['challenge']

        response = post(account_key, challenge['uri'], {
            'resource': 'challenge',
            'type': method,
            'keyAuthorization': auth['key_authorization'],
        })
        if str(response.status_code).startswith('2'):
            return True

        # if retrieve_verification(acme, domain, auth, method):
        #     done.add(domain)
        # else:
        #     failed.add(domain)


