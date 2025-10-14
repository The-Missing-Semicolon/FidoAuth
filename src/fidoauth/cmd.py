"""
Implementation of commandline utilities assocaited with FidoAuth.
"""

import json
import base64
import argparse
import random

from fido2.server import U2FFido2Server, PublicKeyCredentialRpEntity
from fido2.webauthn import AttestationObject, CollectedClientData

from . import common
from . import config

def generate_key():
    """
    Generate the mod_auth_tkt key, and write it to the path specified by `mod_tkt_config` in the config file.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--digest-type", default="SHA512", choices=["MD5", "SHA256", "SHA512"])
    args = parser.parse_args()

    auth_secret = f"{random.SystemRandom().getrandbits(8*64):0128x}"

    config_contents = f"""
# This config was auto generated, run generate_key to recreate
TKTAuthSecret "{auth_secret}"
TKTAuthDigestType {args.digest_type}
"""

    common.touch_conf_file(config.MOD_TKT_CONFIG_FILE)
    with open(config.MOD_TKT_CONFIG_FILE, "w", encoding="utf8") as f:
        f.write(config_contents)

def save_creds():
    """
    Save FIDO and password credentials to the credential database. This function uses the authenticator plugin to prompt ofr the password if necessary.
    """

    parser = argparse.ArgumentParser()
    parser.add_argument("username")
    parser.add_argument("client_data")
    parser.add_argument("attestation_object")
    args = parser.parse_args()

    #TODO: Create creds file if it doesn't already exist

    args.client_data = CollectedClientData(base64.b64decode(args.client_data))
    args.attestation_object = AttestationObject(base64.b64decode(args.attestation_object))

    rp = PublicKeyCredentialRpEntity('FIDO2 Auth Server', config.HOST)
    server = U2FFido2Server('https://' + config.HOST, rp)

    creds, passhash = common.get_raw_creds_for_user(args.username)
    if passhash is None:
        passhash = config.get_authenticator().get_password(args.username)

    common.touch_conf_file(config.MOD_TKT_CONFIG_FILE)

    with open(config.CHALLENGE_FILE, encoding="utf8") as challenge_file:
        auth_data = server.register_complete(json.loads(challenge_file.read()), args.client_data, args.attestation_object)
        if auth_data.credential_data not in creds:
            with open(config.CREDS_FILE, 'a', encoding="utf8") as creds_file:
                creds_file.write(f'{args.username} {base64.b64encode(auth_data.credential_data).decode("ascii")} {passhash}\n')
            print(f"Credentials for {args.username} saved successfully")
        else:
            print(f"Credentials for {args.username} already registered")
