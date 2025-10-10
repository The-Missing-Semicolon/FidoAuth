"""
Base Authenticator plugin definition
"""

import fidoauth.common

class BaseAuthenticator:
    """
    Base Authenticator plugin definition that defines the interface for Authenticator classes
    """
    def Authenticate(self, username, password, passhash):
        """
        Authenticate function takes a username, password, and optionally a password hash. If the username/password is
        'correct' it can return a list of cookies. If it is incorrect, it throws an exception.
        """
        del username, password, passhash # Unused
        raise fidoauth.common.AuthenticationError("Not implemented")

    def Logout(self, get_query, post_query, remote_addr):
        del get_query, post_query, remote_addr # Unused
        headers = [('Set-Cookie', "auth_tkt=invalid; Path=/")]
        return "200 OK", headers, "".encode()

    def GetPassword(self, username):
        del username # Unused
        return "external_password"
