#!/usr/bin/python3
from mkpy.utility import *
import google_utility as google
import hashlib
import traceback

import mimetypes
from googleapiclient.http import MediaFileUpload

import pdb

dump_fname = 'full_file_dump'
file_dict_fname = 'file_dict'
file_tree_fname = 'file_tree'
file_name_tree_fname = 'file_name_tree'
local_file_name_tree_fname = 'local_file_name_tree'
to_upload_fname = 'to_upload'

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
        print ('Detected partially complete dump, starting with from stored page token.')
        parameters['pageToken'] = store_get('nextPageToken')
        files = pickle_load (dump_fname)

    while True:
        try:
            r = google.get('https://www.googleapis.com/drive/v3/files', params=parameters)
        except Exception as e:
            print ('Error while performing request to Google, dump can be restarted by re running the command.')
            print (traceback.format_exc())
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

    pickle_dump (files, dump_fname)
    print (f'Total: {len(files)}')

def tree_file_dump ():
    parameters = {'fields':'nextPageToken,files(id,mimeType,name,md5Checksum,parents)', 'pageSize':1000, 'q':"'root' in parents"}

    # TODO: Implement this. The idea is to have a tree based traversal of
    # google drive. This traversal would be more useful for partial exploration
    # of the file tree. The tricky part of doing this, will be handling a
    # failed request, because we need to keep the partial state from before, in
    # order to resume the tree traversal from the same place where we left.

    files = []

    pickle_dump (files, 'full_file_dump')
    print (f'Total: {len(files)}')

def build_file_dict():
    file_dict = {}

    files = pickle_load (dump_fname)
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

    pickle_dump (file_dict, file_dict_fname)
    print (f'Created file dictionay: {file_dict_fname}')

def recursive_tree_print(indent, node):
    print (indent + node['name'])
    if 'c' in node.keys():
        for child in node['c']:
            recursive_tree_print(indent + ' ', child)

def build_file_tree():
    file_dict = pickle_load (file_dict_fname)

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

    pickle_dump (roots, file_tree_fname)

def tree_new_child(parent, child_id, child_name):
    new_child = {'id': child_id, 'name': child_name}
    tree_set_child (parent, new_child)
    return new_child

def tree_set_child(parent, child):
    if 'c' not in parent.keys():
        parent['c'] = {}

    if child['name'] not in parent['c'].keys():
        parent['c'][child['name']] = child
    else:
        if 'duplicateNames' not in parent['c'][child['name']].keys():
            parent['c'][child['name']]['duplicateNames'] = []
        parent['c'][child['name']]['duplicateNames'].append(child['id'])
        print(f"Found file with existing name '{child['name']}' in directory '{parent['name']}': (old: {parent['c'][child['name']]['id']}) {child['id']}")

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
    file_dict = pickle_load (file_dict_fname)

    root = {}
    for f_id, f in file_dict.items():
        if 'parents' in f.keys():
            for parent_id in f['parents']:
                if parent_id in file_dict.keys():
                    tree_set_child (file_dict[parent_id], f)
        else:
            root[f['name']] = f

    pickle_dump (root, file_name_tree_fname)

def lookup_path (root, path_lst):
    curr_path = ''
    node = root
    for dirname in path_lst:
        curr_path = path_cat(curr_path, dirname)
        if 'c' in node.keys() and dirname in node['c'].keys():
            node = node['c'][dirname]
        else:
            print (f"File doesn't exist: {curr_path}")
    return node

def path_as_list(path):
    # This is uglier than I wanted because, oddly enough
    #       ''.split(' ') returns ['']
    # but
    #       ''.split() returns []
    # why?...
    return [] if path.strip(os.sep).strip() == '' else path.strip(os.sep).split(os.sep)

def recursive_name_duplicates_print(path, node):
    if 'duplicateNames' in node.keys():
        print (path)

    if 'c' in node.keys():
        for name, child in node['c'].items():
            recursive_name_duplicates_print(path_cat(path, name), child)

def find_name_duplicates():
    """
    This snip receives an upstream path of a subtree and it prints all distinct
    files with duplicate names.
    """
    # NOTE: It's possible that we get duplicates while building the file name
    # tree but not here. That's because the full file dump contains shared
    # folders to, and here we assume the passed path has the user's 'My Drive'
    # as root.

    path = '/'
    if len(sys.argv) >= 2:
        path = sys.argv[2]
    path_lst = path_as_list(path)

    file_name_tree = pickle_load (file_name_tree_fname)
    node = lookup_path (file_name_tree['My Drive'], path_lst)
    recursive_name_duplicates_print(path, node)

def build_local_file_name_tree():
    path = '.'
    if len(sys.argv) > 2:
        path = sys.argv[2]
    path = os.path.abspath(path_resolve(path))

    path_lst = []
    local_file_name_tree = {}
    for dirpath, dirnames, filenames in os.walk(path):
        for dname in dirnames:
            fpath = path_cat (dirpath, dname)
            if os.path.islink(fpath):
                print (f'Ignoring link to directory {path_cat(fpath)}')

        path_lst = [dirname for dirname in dirpath.strip(os.sep).split(os.sep) if dirname != '.']
        node = local_file_name_tree
        for dirname in path_lst:
            if 'c' not in node.keys():
                node['c'] = {}

            if dirname not in node['c'].keys():
                node['c'][dirname] = {'name':dirname}

            node = node['c'][dirname]
        if 'c' not in node.keys():
            node['c'] = {}

        for fname in filenames:
            hash_md5 = hashlib.md5()
            with open(path_cat(dirpath, fname), "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)

            node['c'][fname] = {'name':fname, 'md5Checksum':hash_md5.hexdigest()}
            print (path_cat(dirpath, fname))

    pickle_dump (local_file_name_tree, local_file_name_tree_fname)

def recursive_tree_compare(path_lst, local, upstream):
    if 'md5Checksum' in local.keys() and 'md5Checksum' in upstream.keys():
        if local['md5Checksum'] != upstream['md5Checksum']:
            print (f'Checksum mismatch: {os.sep.join(path_lst)}')

    elif ('md5Checksum' in local.keys()) != ('md5Checksum' in upstream.keys()):
        print (f'Type mismatch: {os.sep.join(path_lst)}')

    if 'c' in local.keys() and 'c' in upstream.keys():
        both = local['c'].keys() & upstream['c'].keys()
        for fname in both:
            local_f = local['c'][fname]
            upstream_f = upstream['c'][fname]
            recursive_tree_compare(path_lst + [fname], local_f, upstream_f)

        for fname in upstream['c'].keys() - local['c'].keys():
            print (f'Missing locally: {path_cat(os.sep.join(path_lst), fname)}')

        for fname in local['c'].keys() - upstream['c'].keys():
            print (f'Missing upstream: {path_cat(os.sep.join(path_lst), fname)}')

    elif 'c' not in local.keys() and 'c' in upstream.keys():
        for fname in upstream['c'].keys():
            print (f'Missing locally: {path_cat(os.sep.join(path_lst), fname)}')

    elif 'c' in local.keys() and 'c' not in upstream.keys():
        for fname in local['c'].keys():
            print (f'Missing upstream: {path_cat(os.sep.join(path_lst), fname)}')

def recursive_name_tree_print(indent, node):
    print (indent + node['name'])
    if 'c' in node.keys():
        for name, child in node['c'].items():
            recursive_name_tree_print(indent + ' ', child)

def diff():
    if len(sys.argv) > 2:
        local_path = os.path.abspath(path_resolve(sys.argv[2]))
        upstream_path = sys.argv[3]
    else:
        print ('Missing arguments.')
        return

    local_tree = pickle_load(local_file_name_tree_fname)
    local_path_lst = path_as_list(local_path)
    local_subtree = lookup_path (local_tree, local_path_lst)

    upstream_tree = pickle_load(file_name_tree_fname)
    upstream_path_lst = path_as_list(upstream_path)
    upstream_subtree = lookup_path (upstream_tree['My Drive'], upstream_path_lst)

    #recursive_name_tree_print ('', local_subtree)
    #print()
    #recursive_name_tree_print ('', upstream_subtree)
    #print()

    recursive_tree_compare([], local_subtree, upstream_subtree)

def upload_file(service, local_abs_path, upstream_root, upstream_abs_path):
    if not os.path.isfile(local_abs_path):
        print (f"Upload failed because it's not a file: {local_abs_path}")
        return

    # 1. Follow upstream tree until we find something that doesn't exist.
    path_lst = path_as_list(upstream_abs_path)
    directory_path = path_lst[:-1]
    node = upstream_root
    missing_directory = False
    missing_idx = 0

    for i, dirname in enumerate(directory_path):
        if 'c' in node.keys() and dirname in node['c'].keys():
            node = node['c'][dirname]
        else:
            missing_directory = True
            missing_idx = i
            break

    # 2. Create missing directories
    parent_lst = [node['id']]
    if missing_directory:
        for dir_name in directory_path[missing_idx:]:
            metadata = {
                'name': dir_name,
                'parents': parent_lst,
                'mimeType': 'application/vnd.google-apps.folder'
            }
            create_folder = service.files().create(body=metadata,
                                                   fields='id').execute()
            node = tree_new_child (node, create_folder.get('id', []), dir_name)
            parent_lst[0] = node['id']
        print (f"In '{os.sep.join(directory_path[:missing_idx])}' created folder(s): {os.sep.join(directory_path[missing_idx:])}")

    # 3. Upload the file
    file_metadata = {'name': path_lst[-1], 'parents': parent_lst}
    data = MediaFileUpload(local_abs_path,
            mimetype=mimetypes.MimeTypes().guess_type(path_lst[-1])[0])
    service.files().create(body=file_metadata,
            media_body=data).execute()
    print (f"{local_abs_path} -> {upstream_abs_path}")

def upload():
    if len(sys.argv) > 2:
        local_path = os.path.abspath(path_resolve(sys.argv[2]))
        upstream_path = sys.argv[3]
    else:
        print ('Missing arguments.')
        return

    upstream_tree = pickle_load(file_name_tree_fname)
    upstream_path_lst = path_as_list(upstream_path)
    upstream_root = upstream_tree['My Drive']

    with open(to_upload_fname, "r") as f:
        file_lst = f.read().strip('\n').split('\n')

    service = google.get_service()
    for f_path in file_lst:
        upstream_abs_path = path_cat(upstream_path, f_path)
        local_abs_path = path_cat(local_path, f_path)

        if os.path.isfile(local_abs_path):
            upload_file (service, local_abs_path, upstream_root, upstream_abs_path)

        elif os.path.isdir(local_abs_path):
            for dirpath, dirnames, filenames in os.walk(local_abs_path):
                if dirpath.find(local_abs_path) == 0:
                    upstream_base = dirpath[len(local_abs_path):]
                    for fname in filenames:
                        upstream_file_path = path_cat (upstream_abs_path, upstream_base, fname)
                        upload_file (service, path_cat(dirpath, fname), upstream_root, upstream_file_path)
                else:
                    print (f"Error creating upstream path for: {dirpath} (local: {local_abs_path})")

        else:
            print (f'Skipping unknown file type (link?): {local_abs_path}')

if __name__ == "__main__":
    # Everything above this line will be executed for each TAB press.
    # If --get_completions is set, handle_tab_complete() calls exit().
    handle_tab_complete ()

    pymk_default()

