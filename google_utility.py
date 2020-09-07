from mkpy.utility import *

from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import TokenExpiredError

import webbrowser

import http.server
import socketserver
import urllib.parse as urlparse
from urllib.parse import parse_qs

# Client secret configuration file, downloaded from the Google Console
client_secret_fname = 'client_secret.json'

# File used to cache the received token
token_fname = '.token'

# Constants specific to Google's OAuth implementation
authorization_base_url = 'https://accounts.google.com/o/oauth2/v2/auth'
token_url = 'https://oauth2.googleapis.com/token'
scope = ['https://www.googleapis.com/auth/drive.metadata.readonly']

redirect_port = 4538
authorization_code = None

class AuthorizationRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        global authorization_code 
        parsed = urlparse.urlparse(self.path)
        authorization_code = parse_qs(parsed.query)['code'][0]

        # TODO: Have a nicer page with this message.
        html_data = b'Authentication was successful, you can go back to the terminal.'

        self.send_response(200)
        self.send_header("Content-type", 'text/html')
        self.send_header("Content-Length", len(html_data))
        self.send_header("Last-Modified", self.date_time_string())
        self.end_headers()
        self.wfile.write(html_data)

def client_credentials():
    if not path_exists(client_secret_fname):
        err ('error: ', end='')
        print('client credentials not found')
        print ('  Go to Google Console, create a project and its client_id'
                ' and client_secret, then download the client secret json'
                ' file and place it in this directory.')
        exit(-1)

    else:
        j = json_load (client_secret_fname)
        return j['installed']['client_id'], j['installed']['client_secret'],

def google_authenticate():
    token = None
    try:
        token = py_literal_load (token_fname)

    except FileNotFoundError:
        ##################################
        ## Authenticate for the first time

        client_id, client_secret = client_credentials()
        redirect_uri = 'http://127.0.0.1:' + str(redirect_port)

        # Create authentication request URL and open web browser with it
        oauth = OAuth2Session(client_id, scope=scope, redirect_uri=redirect_uri)
        authorization_url, state = oauth.authorization_url(authorization_base_url, access_type="offline", prompt="select_account")
        webbrowser.open_new_tab(authorization_url)

        # Listen for the authentication result
        httpd = socketserver.TCPServer(('localhost', redirect_port), AuthorizationRequestHandler)
        httpd.handle_request()
        httpd.server_close()

        # Get a token with the received authentication code
        token = oauth.fetch_token(token_url=token_url, code=authorization_code, client_id=client_id, client_secret=client_secret)
        py_literal_dump (token, token_fname)

    return token

def __google_get(*args, **kwargs):
    token = google_authenticate ()

    client_id, client_secret = client_credentials()
    oauth = OAuth2Session(client_id, token=token)
    return oauth.get(*args, **kwargs)

def get(*args, **kwargs):
    r = None
    
    try:
        r = __google_get(*args, **kwargs)

    except TokenExpiredError as e:
        ####################
        ## Refresh the token

        client_id, client_secret = client_credentials()
        token = oauth.refresh_token(token_url, client_id=client_id, client_secret=client_secret)
        py_literal_dump (token, token_fname)

        # Retry once
        r = __google_get(*args, **kwargs)

    return r
