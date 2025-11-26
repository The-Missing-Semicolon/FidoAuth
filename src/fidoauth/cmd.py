"""
Implementation of commandline utilities assocaited with FidoAuth.
"""

import json
import base64
import argparse
import random

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

    common.save_creds(args.username, base64.urlsafe_b64decode(args.client_data), base64.urlsafe_b64decode(args.attestation_object))