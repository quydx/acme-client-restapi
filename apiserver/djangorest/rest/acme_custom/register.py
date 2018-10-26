"""
Account registration.
"""

import logging
import os

from manuale.account import Account
from manuale.acme import Acme
from manuale.errors import ManualeError, AccountAlreadyExistsError
from manuale.crypto import (
    generate_rsa_key,
    load_private_key,
)


logger = logging.getLogger(__name__)

def register(server, account_path, email, key_file):

    if key_file:
        try:
            with open(key_file, 'rb') as f:
                account = Account(key=load_private_key(f.read()))
        except (ValueError, AttributeError, TypeError, IOError) as e:
            logger.error("Couldn't read key.")
            raise ManualeError(e)
    else:
        logger.info("Generating a new account key. This might take a second.")
        account = Account(key=generate_rsa_key(4096))
        logger.info("Key generated.")

    # Register
    acme = Acme(server, account)
    logger.info("Registering...")
    try:
        registration = acme.register(email)

        # If the server has terms of service, prompt the user to confirm
        # TODO: This is a really stupid flow. Keep an eye out on this issue:
        # https://github.com/ietf-wg-acme/acme/issues/59 and hope they fix it.
        if registration.terms:
            acme.update_registration({ 'agreement': registration.terms })
            logger.info("Updated account with agreement.")

        logger.info("Account {} created.".format(account.uri))
    except IOError as e:
        logger.error("Registration failed due to a connection or request error.")
        raise ManualeError(e)

    # Write account
    directory = os.path.dirname(os.path.abspath(account_path))
    os.makedirs(directory, exist_ok=True)
    with open(account_path, 'wb') as f:
        os.chmod(account_path, 0o600)
        f.write(account.serialize())

    logger.info("Wrote account to {}.".format(account_path))
    logger.info("")
    logger.info("What next? Verify your domains with 'authorize' and use 'issue' to get new certificates.")