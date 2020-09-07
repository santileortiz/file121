#!/usr/bin/python3
from mkpy.utility import *
import google_utility as google

def default ():
    target = store_get ('last_snip', default='example_procedure')
    call_user_function(target)

def list_drive_files ():
    parameters = {'fields':'files(id,name,parents)'}
    r = google.get('https://www.googleapis.com/drive/v3/files', params=parameters)
    print (r.text)

if __name__ == "__main__":
    # Everything above this line will be executed for each TAB press.
    # If --get_completions is set, handle_tab_complete() calls exit().
    handle_tab_complete ()

    pymk_default()

