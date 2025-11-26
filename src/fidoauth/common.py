"""
Common helper functions
"""

import re
import base64
import grp
import json
import os
from pathlib import Path

from fido2.server import Fido2Server, PublicKeyCredentialRpEntity
from fido2.webauthn import AttestedCredentialData, AuthenticatorAttestationResponse, AttestationObject, CollectedClientData, RegistrationResponse

from . import config

class AuthenticationError(Exception):
    """
    Generic Authentication Error
    """
    #TODO: Make an error page render when this gets thrown...

def get_raw_creds_for_user(username):
    """
    Parse the credential file and return the users password hash along with a list of possible fido credentials.
    """
    split = re.compile(r"([^\s]*)\s+([^\s]*)\s+([^\s]*)")

    creds = []
    passhash = None
    try:
        with open(config.CREDS_FILE, 'r', encoding="utf8") as f:
            for line in f:
                (user, cred_data, linehash) = split.match(line).groups()
                if username.lower() == user.lower():
                    if passhash is None:
                        passhash = linehash
                    creds.append(base64.urlsafe_b64decode(cred_data))
    except FileNotFoundError:
        pass

    return creds, passhash

def get_creds_for_user(username):
    """
    Return the unpacked credentials for the specified user
    """
    raw_creds, passhash = get_raw_creds_for_user(username)
    creds = []
    for raw_cred in raw_creds:
        cred, _ = AttestedCredentialData.unpack_from(raw_cred)
        creds.append(cred)
    return creds, passhash

def touch_conf_file(path):
    """
    Ensure credentials file owner is root:ww-data, permissions are u=rw,g=r so that the server process can't change the creds
    """
    Path(path).touch(0o640)
    Path(path).chmod(0o640)
    gid = grp.getgrnam(config.SERVER_USER).gr_gid
    os.chown(path, 0, gid)

def save_creds(username, client_data, attestation_object):
    #TODO: Create creds file if it doesn't already exist
    rp = PublicKeyCredentialRpEntity(name='FIDO2 Auth Server', id=config.HOST)
    server = Fido2Server(rp=rp)

    attestation_response = AuthenticatorAttestationResponse(client_data=CollectedClientData(client_data), attestation_object=AttestationObject(attestation_object))
    registration_response = RegistrationResponse(raw_id=username.encode("utf-8"), response=attestation_response)
    

    creds, passhash = get_raw_creds_for_user(username)
    if passhash is None:
        passhash = config.get_authenticator().get_password(username)

    #touch_conf_file(config.MOD_TKT_CONFIG_FILE)

    with open(config.CHALLENGE_FILE, encoding="utf8") as challenge_file:
        auth_data = server.register_complete(state=json.loads(challenge_file.read()), response=registration_response)
        if auth_data.credential_data not in creds:
            with open(config.CREDS_FILE, 'a', encoding="utf8") as creds_file:
                creds_file.write(f'{username} {base64.b64encode(auth_data.credential_data).decode("ascii")} {passhash}\n')
            print(f"Credentials for {username} saved successfully")
        else:
            print(f"Credentials for {username} already registered")

