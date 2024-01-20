import sys
import json
import base64
import getpass
import argparse
import random


from pathlib import Path
from fido2.server import U2FFido2Server, PublicKeyCredentialRpEntity
from fido2.webauthn import AttestationObject, CollectedClientData

from . import common
from . import config

def GenerateKey():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--digest-type", default="SHA512", choices=["MD5", "SHA256", "SHA512"])
    args = parser.parse_args()

    auth_secret = '%0128x' % random.SystemRandom().getrandbits(8*64)

    config_contents = f"""
# This config was auto generated, run generate_key to recreate
TKTAuthSecret "{auth_secret}"
TKTAuthDigestType {args.digest_type}
"""

    common.TouchConfFile(config.MOD_TKT_CONFIG_FILE)
    with open(config.MOD_TKT_CONFIG_FILE, "w") as f:
        f.write(config_contents)

def SaveCreds():
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
    
    creds, passhash = common.GetRawCredsForUser(args.username)
    while passhash is None:
        password1 = getpass.getpass(prompt=f"Enter password for {args.username}: ")
        password2 = getpass.getpass(prompt=f"Reenter password for {args.username}: ")
        if password1 == password2:
            passhash = common.PASSWORD_HASHER.hash(password=password1)
    
    common.TouchConfFile(config.MOD_TKT_CONFIG_FILE)
    
    with open(config.CHALLENGE_FILE) as challenge_file:
        auth_data = server.register_complete(json.loads(challenge_file.read()), args.client_data, args.attestation_object)
        if auth_data.credential_data not in creds:
            with open(config.CREDS_FILE, 'a') as creds_file:
                creds_file.write(f'{args.username} {base64.b64encode(auth_data.credential_data).decode("ascii")} {passhash}\n')
            print(f"Credentials for {args.username} saved successfully")
        else:
            print(f"Credentials for {args.username} already registered")