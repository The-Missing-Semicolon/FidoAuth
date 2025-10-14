"""
Authenticator for with Ubiquiti's Unifi Controller. 
"""

import json
import ssl

from urllib import request
from .base import BaseAuthenticator

UNIFI_HOST = "https://127.0.0.1:8443"


def _get_tls_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

class Authenticator(BaseAuthenticator):
    """
    Authenticator class for use with Ubiquiti's Unifi Controller. 
    """
    def authenticate(self, username, password, passhash):
        """
        Authenticator against the Unifi Controller's login API.
        """
        del passhash # unused

        authdata = json.dumps({"username": username, "password": password, "remember": False, "strict":True})
        req = request.Request(f"{UNIFI_HOST}/api/login", data=authdata.encode())
        with request.urlopen(req, context=_get_tls_context()) as resp:
            cookies = []
            for header in resp.getheaders():
                if header[0] == "Set-Cookie":
                    cookies.append(header[1])

        return cookies

    def logout(self, get_query, post_query, remote_addr):
        """
        Logout using the Unifi Controller's logout API.
        """
        del get_query, post_query, remote_addr

        req = request.Request(f"{UNIFI_HOST}/api/logout", data="".encode())
        with request.urlopen(req, context=_get_tls_context()) as resp:
            headers = []
            headers.append(('Set-Cookie', "auth_tkt=invalid; Path=/"))
            for header in resp.getheaders():
                if header[0] == "Set-Cookie":
                    headers.append(header)

        return "200 OK", headers, resp.read()
