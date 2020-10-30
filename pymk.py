#!/usr/bin/python3
from mkpy.utility import *
import google_utility as google

dump_fname = 'full_file_dump'
file_dict_fname = 'file_dict'
file_tree_fname = 'file_tree'
file_name_tree_fname = 'file_name_tree'

def default ():
    target = store_get ('last_snip', default='example_procedure')
    call_user_function(target)

def sequential_file_dump ():
    """
    This requests all file information from google drive and dumps it into a
    file as a python literal list. It gets enough information for us to compare
    the upstream file with one downstream.
    """

    restart = get_cli_bool_opt('--restart')
    progress_flag_name = 'sequentialTraversalInProgress'
    is_in_progress = store_get(progress_flag_name, default=False) and not restart

    parameters = {'fields':'nextPageToken,files(id,name,md5Checksum,parents)', 'pageSize':1000, 'q':'trashed = false'}

    files = []
    if is_in_progress:
        print ('Detected partially complete dump, starting with from page token.')
        parameters['nextPageToken'] = store_get('nextPageToken')
        files = py_literal_load (dump_fname)

    while True:
        try:
            r = google.get('https://www.googleapis.com/drive/v3/files', params=parameters)
        except:
            print ('Error while performing request to Google, dump can be restarted by re running the command.')
            store(progress_flag_name, True)
            break

        if 'files' in r.keys():
            files += r['files']
            print (f'Received: {len(r["files"])} ({files[-1]["id"] if len(files) > 0 else ""})')
        else:
            print (f'Received response without files.')
            print (r)

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
    parameters = {'fields':'nextPageToken,files(id,mimeType,name,md5Checksum,parents)', 'pageSize':1000, 'q':"'root' in parents"}

    # TODO: Implement this. The idea is to have a tree based traversal of
    # google drive. This traversal would be more useful for partial exploration
    # of the file tree. The tricky part of doing this, will be handling a
    # failed request, because we need to keep the partial state from before, in
    # order to resume the tree traversal from the same place where we left.

    files = []

    py_literal_dump (files, 'full_file_dump')
    print (f'Total: {len(files)}')

def build_file_dict():
    file_dict = {}

    files = py_literal_load (dump_fname)
    for f in files:
        new_file_info = {key: value for key, value in f.items()}
        f_id = f['id']
        if f_id in file_dict:
            # This should never happen
            print (f'Found repeated ID {f_id}')
        file_dict[f_id] = new_file_info
    
    # For some reason, the sequential file dump still misses some parents. Here
    # we iterate the dump and check that all parent IDs are resolved.  I even
    # tried setting to true 'includeItemsFromAllDrives' and
    # 'supportsAllDrives', it didn't work.
    #
    # TODO: Maybe these files should be specially marked, like "ghost" files?.
    for f in files:
        if 'parents' in f.keys():
            for parent_id in f['parents']:
                if parent_id not in file_dict.keys():
                    try:
                        r = google.get(f'https://www.googleapis.com/drive/v3/files/{parent_id}')
                    except:
                        print ('Failed to get parent file {parent_id}')
                        # TODO: Maybe if this happens, the correct solution is
                        # to remove the parent reference from the file, so the
                        # tree can be built "normally"?. It's possible we will
                        # end up adding stuff to the root that's not supposed
                        # to be there...

                    file_dict[parent_id] = r
                    print (f'Added ghost file {parent_id}')

    py_literal_dump (file_dict, file_dict_fname)
    print (f'Created file dictionay: {file_dict_fname}')

def recursive_tree_print(indent, node):
    print (indent + node['name'])
    if 'c' in node.keys():
        for child in node['c']:
            recursive_tree_print(indent + ' ', child)

def build_file_tree():
    file_dict = py_literal_load (file_dict_fname)

    roots = []
    for f_id, f in file_dict.items():
        if 'parents' in f.keys():
            for parent_id in f['parents']:
                if parent_id in file_dict.keys():
                    parent = file_dict[parent_id]
                    if 'c' not in parent.keys():
                        parent['c'] = []

                    parent['c'].append(f)
        else:
            roots.append(f)

    py_literal_dump (roots, file_tree_fname)

def build_file_name_tree():
    """
    This transforms the tree from before that uses arrays for the children into
    a version that uses name indexed dictionaries. This is the one we will use
    to query the upstream existance and MD5 hash of a local file when doing the
    diff.
    """

    # Google Drive allows multiple files with the same name in the same
    # directory. File systems on the other hand, don't allow this. Also,
    # Windows is case insensitive while Unix file systems are case sensitive.
    # When downloading a subtree from Google Drive we need to make sure the
    # upstream file tree follows the operating system's constraints before we
    # even start. We may need to ask the user to fix the problems, or at least
    # make them know there's something going on that they may not be expecting.
    # This function will expose those problems if they exist.

    # TODO: Implement this as a tree traversal
    # TODO: Implement a version of this that considers names equal in a case
    # insensitive way.
    file_dict = py_literal_load (file_dict_fname)

    root = {}
    for f_id, f in file_dict.items():
        if 'parents' in f.keys():
            for parent_id in f['parents']:
                if parent_id in file_dict.keys():
                    parent = file_dict[parent_id]
                    if 'c' not in parent.keys():
                        parent['c'] = {}

                    if f['name'] not in parent['c'].keys():
                        parent['c'][f['name']] = f
                    else:
                        if 'duplicateNames' not in parent['c'][f['name']].keys():
                            parent['c'][f['name']]['duplicateNames'] = []
                        parent['c'][f['name']]['duplicateNames'].append(f['id'])
                        print(f"Found file with existing name '{f['name']}' in directory '{parent['name']}': (old: {parent['c'][f['name']]['id']}) {f['id']}")
        else:
            root[f['name']] = f

    py_literal_dump (root, file_name_tree_fname)

def recursive_name_duplicates_print(path, node):
    if 'duplicateNames' in node.keys():
        print (path)

    if 'c' in node.keys():
        for name, child in node['c'].items():
            recursive_name_duplicates_print(path_cat(path, name), child)

def find_name_duplicates():
    # NOTE: It's possible that we get duplicates while building the file name
    # tree but not here. That's because the full file dump contains shared
    # folders to, and here we assume the passed path has the user's 'My Drive'
    # as root.

    # This is uglier than I wanted because oddly enough
    #       ''.split(' ') returns ['']
    # but
    #       ''.split() returns []
    # why?...
    path = '/'
    if len(sys.argv) >= 2:
        path = sys.argv[2]
    path_lst = [] if path.strip('/').strip() == '' else path.strip("/").split("/")

    file_name_tree = py_literal_load (file_name_tree_fname)

    curr_path = ''
    node = file_name_tree['My Drive']
    for dirname in path_lst:
        curr_path = path_cat(curr_path, dirname)
        if 'c' in node.keys() and dirname in node['c'].keys():
            node = node['c'][dirname]
        else:
            print (f"File doesn't exist: {curr_path}")

    recursive_name_duplicates_print(path, node)

# TODO: Implement a diff function between a local folder and upstream

if __name__ == "__main__":
    # Everything above this line will be executed for each TAB press.
    # If --get_completions is set, handle_tab_complete() calls exit().
    handle_tab_complete ()

    pymk_default()

