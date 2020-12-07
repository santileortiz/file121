from mkpy.utility import *

from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import TokenExpiredError

import webbrowser

import http.server
import socketserver
import urllib.parse as urlparse
from urllib.parse import parse_qs


# TODO: How would things change if I use this?
#from google_auth_oauthlib.flow import Flow
import pickle
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

# Client secret configuration file, downloaded from the Google Console
client_secret_fname = 'client_secret.json'

# File used to cache the received token
token_fname = '.token'

# Constants specific to Google's OAuth implementation
authorization_base_url = 'https://accounts.google.com/o/oauth2/v2/auth'
token_url = 'https://oauth2.googleapis.com/token'
scope = ['https://www.googleapis.com/auth/drive']

redirect_port = 4538
authorization_code = None

class AuthorizationRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        global authorization_code 
        parsed = urlparse.urlparse(self.path)

        # TODO: If authentication fails this probably crashes, should handle
        # this case better.
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

def oauth_session ():
    client_id, client_secret = client_credentials()
    redirect_uri = 'http://127.0.0.1:' + str(redirect_port)

    return OAuth2Session(client_id, scope=scope, redirect_uri=redirect_uri), client_id, client_secret

def google_authenticate():
    # TODO: Try other authentication flows?. Implicit authentication or API key could also be useful.

    token = None
    try:
        token = py_literal_load (token_fname)

    except FileNotFoundError:
        ##################################
        ## Authenticate for the first time

        # Create authentication request URL and open web browser with it
        oauth, client_id, client_secret = oauth_session()
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

    response = oauth.get(*args, **kwargs)
    if response.status_code != 200:
        print (f'Got unexpected response code: {response.json()}')
        data = None
    else:
        data = response.json()

    return data

def get(*args, **kwargs):
    r = None

    # Sometimes requests get stuck forever, the stack trace when terminating
    # looks a lot like the one in [1] according to [2] calls don't timeout by
    # default, so we ensure we have a timeout here.
    #
    # [1]: https://stackoverflow.com/questions/54227770/request-get-is-getting-stuck/54257352
    # [2]: https://requests.readthedocs.io/en/master/user/advanced/#timeouts
    if 'timeout' not in kwargs.keys():
        kwargs['timeout'] = 150

    try:
        r = __google_get(*args, **kwargs)

    except TokenExpiredError as e:
        ####################
        ## Refresh the token

        oauth, client_id, client_secret = oauth_session()
        expired_token = py_literal_load (token_fname)
        token = oauth.refresh_token(token_url, client_id=client_id, client_secret=client_secret, refresh_token=expired_token['refresh_token'])
        py_literal_dump (token, token_fname)

        # Retry once
        r = __google_get(*args, **kwargs)

    return r

def get_service():
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'client_secret.json', scope)
            creds = flow.run_local_server(port=0)

        # Dump credentials
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    return build('drive', 'v3', credentials=creds)

def request_execute_cli(request):
    # NOTE: The cursor is at the beginning, I leave one space character so it
    # doesn't overlap the text.
    print (f' [0%]', file=sys.stderr, end='')
    response = None
    while response is None:
        try:
            status, response = request.next_chunk()
            if status:
                print (f'\r [{status.progress() * 100:.2f}%]', file=sys.stderr, end='')

        except OSError:
            response = None
            print (f'\r', file=sys.stderr, end='')
            print (f'Error uploading chunk. Retrying...')
            print (f' [0%]', file=sys.stderr, end='')

        print (f'\r', file=sys.stderr, end='')
