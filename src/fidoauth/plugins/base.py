"""
Base Authenticator plugin definition
"""

import fidoauth.common

class BaseAuthenticator:
    """
    Base Authenticator plugin definition that defines the interface for Authenticator classes
    """
    def authenticate(self, username, password, passhash):
        """
        Authenticate function takes a username, password, and optionally a password hash. If the username/password is
        'correct' it can return a list of cookies. If it is incorrect, it throws an exception.
        """
        del username, password, passhash # Unused
        raise fidoauth.common.AuthenticationError("Not implemented")

    def logout(self, get_query, post_query, remote_addr):
        """
        Logout. The base implementation invalidates the `mod_auth_tkt` cookie.
        """
        del get_query, post_query, remote_addr # Unused
        headers = [('Set-Cookie', "auth_tkt=invalid; Path=/")]
        return "200 OK", headers, "".encode()

    def get_password(self, username):
        """
        This method is invoked by the `save_creds` command line. If necessary, it can prompt the user for a password.
        """
        del username # Unused
        return "external_password"
