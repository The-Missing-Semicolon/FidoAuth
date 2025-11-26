import base64
import json
import logging
import pytest
import random
import sys
import tempfile

from bs4 import BeautifulSoup
from mock_device import MockDevice

# Override the logger to log to the terminal instead of the default log file
import fidoauth.config
import fidoauth.common

def get_logger():
    """
    Returns the logger object pointing to the log file specified in the configuration.
    """
    logger = logging.getLogger(__file__)
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s (%(filename)s:%(lineno)d)')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    return logger

fidoauth.config.get_logger = get_logger

import fidoauth.server
import fidoauth.plugins.password

class MockAuthenticator(fidoauth.plugins.password.Authenticator):
    def get_password(self, username):
        return fidoauth.plugins.password.PASSWORD_HASHER.hash(password="this is a test password")

def test_registration():
    with tempfile.NamedTemporaryFile() as challenge_file, tempfile.NamedTemporaryFile() as creds_file:
        challenge_file.close()
        creds_file.close()
        fidoauth.config.CHALLENGE_FILE = challenge_file.name
        fidoauth.config.CREDS_FILE = creds_file.name
        fidoauth.config.HTTP_ORIGIN = "https://test.fido"
        fidoauth.config.HOST = "test.fido"
        fidoauth.config.MOD_TKT_SECRET =  f"{random.SystemRandom().getrandbits(8*64):0128x}"
        fidoauth.config.MOD_TKT_DIGEST_TYPE = "SHA512"
        fidoauth.config.get_authenticator = lambda : MockAuthenticator()

        server = fidoauth.server.FidoAuthServer()

        status, headers, output = server.registration(None, None, None)
        assert status == "200 OK"

        status, headers, output = server.begin_registration(None, {"username" : "testuer"}, None)
        assert status == "200 OK"

        # Parse the challenge json out of the response
        # TODO: This is horribly fragile....
        challenge = json.loads(output.split(b"\n")[8].split(b" = ")[1].strip(b";"))
        #challenge['publicKey']['user']['id'] = bytes(challenge['publicKey']['user']['id'])
        challenge['publicKey']['user']['id'] = challenge['publicKey']['user']['id']
        #challenge['publicKey']['challenge'] = bytes(challenge['publicKey']['challenge'])
        challenge['publicKey']['challenge'] = challenge['publicKey']['challenge']

        device = MockDevice()
        response = device.create(challenge, "https://test.fido")

        fidoauth.common.save_creds("testuser", response["response"]["clientDataJSON"], response["response"]["attestationObject"])

        status, headers, output = server.login({"back" : ["testing"]}, None, None)
        assert status == "200 OK"

        soup = BeautifulSoup(output, 'html.parser')
        auth_id = next(filter(lambda x: x["name"] == "auth_id", soup.find_all("input")))["value"]
    
        assert auth_id is not None
    
        status, headers, output = server.begin_authenticate({"back" : ["testing"]}, {"auth_id" : [auth_id], "username" : ["testuser"], "password" : ["this is a test password"]}, None)
        assert status == "200 OK"

        challenge = json.loads(output.split(b"\n")[8].split(b" = ")[1].strip(b";"))
        #challenge['publicKey']['challenge'] = bytes(challenge['publicKey']['challenge'])
        #challenge['publicKey']['allowCredentials'][0]['id'] = bytes(challenge['publicKey']['allowCredentials'][0]['id'])
        
        response = device.get(challenge, "https://test.fido")

        server.complete_authentication({"back" : ["testing"]}, {"auth_id" : [auth_id],
                                                                "username": ["testuser"],
                                                                "id" : [base64.b64encode(response["rawId"])],
                                                                "clientDataJSON" : [base64.b64encode(response["response"]["clientDataJSON"])],
                                                                "authenticatorData" : [base64.b64encode(response["response"]["authenticatorData"])],
                                                                "signature" : [base64.b64encode(response["response"]["signature"])]}, "127.0.0.1")
        

        

