import fidoauth.common

class BaseAuthenticator:
    def Authenticate(self, username, password, passhash):
        raise common.AuthenticationError("Not implemented")

    def Logout(self, get_query, post_query, remote_addr):
        headers = [('Set-Cookie', "auth_tkt=invalid; Path=/")]
        return "200 OK", headers, "".encode()