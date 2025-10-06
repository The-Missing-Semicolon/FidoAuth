from urllib.parse import parse_qs

from . import common
from . import config
from . import server

def application(environ, start_response):
    origin = environ.get('HTTP_ORIGIN', config.HTTP_ORIGIN)
    if origin != config.HTTP_ORIGIN:
        raise Exception(f"Unexpected Origin, expected '{config.HTTP_ORIGIN}' got '{origin}'")

    get_query = parse_qs(environ.get('QUERY_STRING', ""))
    post_query = parse_qs(environ['wsgi.input'].read().decode())
    remote_addr = environ["REMOTE_ADDR"]

    try:
        if environ["PATH_INFO"] == "/register":
            status, headers, output = server.Registration(get_query, post_query, remote_addr)
        elif environ["PATH_INFO"] == "/registration":
            status, headers, output = server.BeginRegistration(get_query, post_query, remote_addr)
        elif environ["PATH_INFO"] == "/login":
            status, headers, output = server.Login(get_query, post_query, remote_addr)
        elif environ["PATH_INFO"] == "/authenticate":
            status, headers, output = server.BeginAuthenticate(get_query, post_query, remote_addr)
        elif environ["PATH_INFO"] == "/finish":
            status, headers, output = server.CompleteAuthentication(get_query, post_query, remote_addr)
        else:
            config.GetLogger().error("Access to unknown page %s from %s", environ["PATH_INFO"], environ["REMOTE_ADDR"])
            status = "404 Not Found"
            headers = [('Content-type', 'text/html')]
            output  = server.RenderError(environ, "Page not found")

    except common.AuthenticationError as e:
        headers = [('Content-type', 'text/html')]
        status = "200 OK"
        output = server.RenderError(environ, str(e))
    except:
        config.GetLogger().exception("An error occured handling a request from %s", environ["REMOTE_ADDR"])
        headers = [('Content-type', 'text/html')]
        status = "500 Internal Server Error"
        output = server.RenderError(environ, "An error occured")

    start_response(status, headers)
    return [output]