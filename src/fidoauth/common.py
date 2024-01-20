import re
import base64
import grp
import os
from pathlib import Path

from fido2.webauthn import AttestedCredentialData

import argon2

from . import config

PASSWORD_HASHER = argon2.PasswordHasher()

class AuthenticationError(Exception):
    #TODO: Make an error page render when this gets thrown...
    pass

def GetRawCredsForUser(username):
    split = re.compile("([^\s]*)\s+([^\s]*)\s+([^\s]*)")

    creds = []
    passhash = None
    try:
        with open(config.CREDS_FILE, 'r') as f:
            for line in f:
                (user, cred_data, hash) = split.match(line).groups()
                if username.lower() == user.lower():
                    if passhash is None:
                        passhash = hash
                    creds.append(base64.b64decode(cred_data))
    except FileNotFoundError:
        pass
    
    return creds, passhash

def GetCredsForUser(username):
    raw_creds, passhash = GetRawCredsForUser(username)
    creds = []
    for raw_cred in raw_creds:
        cred, _ = AttestedCredentialData.unpack_from(raw_cred)
        creds.append(cred)
    return creds, passhash

def TouchConfFile(path):
    #Ensure owner is root:ww-data, permissions are u=rw,g=r so that the server process can't change the creds
    Path(path).touch(0o640)
    Path(path).chmod(0o640)
    gid = grp.getgrnam(config.SERVER_USER).gr_gid
    os.chown(path, 0, gid)
