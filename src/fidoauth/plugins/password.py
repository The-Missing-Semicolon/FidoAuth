"""
Plugin for performing password authentication using the local password database, hashed using argon2
"""

import getpass

import argon2

import fidoauth.config
import fidoauth.common

from .base import BaseAuthenticator

PASSWORD_HASHER = argon2.PasswordHasher()
LOGGER = fidoauth.config.GetLogger()

class Authenticator(BaseAuthenticator):
    """
    Password authenticator class
    """
    def Authenticate(self, username, password, passhash):
        if passhash is not None:
            PASSWORD_HASHER.verify(passhash, password)
            LOGGER.debug("Password for %s accepted", username)
            #TODO: if common.PASSWORD_HASHER.check_needs_rehash(passhash):

            return []

        LOGGER.warning("Password not found for %s", username)
        raise fidoauth.common.AuthenticationError("Invalid username or password")

    def GetPassword(self, username):
        while True:
            password1 = getpass.getpass(prompt=f"Enter password for {username}: ")
            password2 = getpass.getpass(prompt=f"Reenter password for {username}: ")
            if password1 == password2:
                return PASSWORD_HASHER.hash(password=password1)
