#!/usr/bin/python3
from mkpy.utility import *
import google_utility as google

def default ():
    target = store_get ('last_snip', default='example_procedure')
    call_user_function(target)

def sequential_file_dump ():
    restart = get_cli_bool_opt('--restart')
    progress_flag_name = 'sequentialTraversalInProgress'
    is_in_progress = store_get(progress_flag_name, default=False) and not restart

    dump_fname = 'full_file_dump'
    parameters = {'fields':'nextPageToken,files(id,name,md5Checksum,parents)', 'pageSize':1000}

    files = []
    if is_in_progress:
        print ('Detected partially complete dump, starting with from page token.')
        parameters['nextPageToken'] = store_get('nextPageToken')
        files = py_literal_load (dump_fname)

    while True:
        try:
            r = google.get('https://www.googleapis.com/drive/v3/files', params=parameters)
        except e:
            print ('Error while performing request to Google, dump can be restarted by re running the command.')
            store(progress_flag_name, True)
            break

        files += r['files']
        print (f'Received: {len(r["files"])} ({files[-1]["id"] if len(files) > 0 else ""})')

        if 'nextPageToken' not in r.keys():
            # Successfully reached the end of the full file list
            store(progress_flag_name, False)
            break
        else:
            nextPage_token = r['nextPageToken']
            store('nextPageToken', nextPage_token)
            parameters['pageToken'] = nextPage_token

    py_literal_dump (files, dump_fname)
    print (f'Total: {len(files)}')

def tree_file_dump ():
    parameters = {'fields':'nextPageToken,files(id,name,md5Checksum,parents)', 'pageSize':1000, 'q':"'root' in parents"}

    # TODO: Implement this. The idea is to have a tree based traversal of
    # google drive. This traversal would be more useful for partial exploration
    # of the file tree. The tricky part of doing this, will be handling a
    # failed request, because we need to keep the partial state from before, in
    # order to resume the tree traversal from the same place where we left.

    files = []

    py_literal_dump (files, 'full_file_dump')
    print (f'Total: {len(files)}')


# TODO: Implement a diff function between a local folder and upstream

if __name__ == "__main__":
    # Everything above this line will be executed for each TAB press.
    # If --get_completions is set, handle_tab_complete() calls exit().
    handle_tab_complete ()

    pymk_default()

