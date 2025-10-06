import json
import ssl

from urllib import request
from . import BaseAuthenticator

UNIFI_HOST = "https://127.0.0.1:8443"


def _GetTlsContext():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

class Authenticator(BaseAuthenticator):
    def Authenticate(self, username, password, passhash):
        authdata = json.dumps({"username": username, "password": password, "remember": False, "strict":True})
        req = request.Request(f"{UNIFI_HOST}/api/login", data=authdata.encode())
        resp = request.urlopen(req, context=_GetTlsContext())

        cookies = []
        for header in resp.getheaders():
            if header[0] == "Set-Cookie":
                cookies.append(header[1])

        return cookies

    def Logout(self, get_query, post_query, remote_addr):
        req = request.Request(f"{UNIFI_HOST}/api/logout", data="".encode())
        resp = request.urlopen(req, context=_GetTlsContext())
        
        headers = []
        headers.append(('Set-Cookie', "auth_tkt=invalid; Path=/"))
        for header in resp.getheaders():
            if header[0] == "Set-Cookie":
                headers.append(header)

        return "200 OK", headers, resp.read()