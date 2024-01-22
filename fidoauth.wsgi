import fidoauth.wsgi
def application(environ, start_response):
    return fidoauth.wsgi.application(environ, start_response)