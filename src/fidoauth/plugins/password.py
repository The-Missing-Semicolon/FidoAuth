import argon2

import fidoauth.config

PASSWORD_HASHER = argon2.PasswordHasher()
LOGGER = fidoauth.config.GetLogger()

class Authenticator:
    def Authenticate(self, username, password, passhash):
        if passhash != None:
            PASSWORD_HASHER.verify(passhash, password)
            LOGGER.debug("Password for %s accepted", username)
            #TODO: if common.PASSWORD_HASHER.check_needs_rehash(passhash):

            return []
        else:
            LOGGER.warning("Password not found for %s", username)
            raise common.AuthenticationError("Invalid username or password")

    def Logout(self, get_query, post_query, remote_addr):
        return super().Logout(get_query, post_query, remote_addr)