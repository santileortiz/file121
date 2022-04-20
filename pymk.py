#!/usr/bin/python3
from mkpy.utility import *
import google_utility as google
from datetime import datetime, timezone
import dateutil.parser
import hashlib
import traceback
import stat
import shutil

import mimetypes
from googleapiclient.http import MediaFileUpload

import pdb

# This directory contains files that can be regenerated somehow. Users
# shouldn't try backing up things in here, it shouldn't be necessary.
cache_dir = os.path.abspath(path_resolve('~/.cache/file121'))
ensure_dir(cache_dir)

# This directory contains all user data. This is users should back up.
base_dir = os.path.abspath(path_resolve('~/.file121'))
ensure_dir(base_dir)

# TODO: Unify file_dict and file_tree into a single file. Create a common type
# of datastructure for local and upstream tree files.
upstream_file_dict_fname = path_cat (cache_dir, 'upstream_file_dict')
upstream_file_tree_fname = path_cat (cache_dir, 'upstream_file_tree')
local_file_tree_fname    = path_cat (cache_dir, 'local_file_tree')

changes_token_prop = 'changes_token'
bindings_prop = 'bindings'

def load_upstream_file_dict():
    return pickle_load (upstream_file_dict_fname)

def store_upstream_file_dict(file_dict):
    return pickle_dump (file_dict, upstream_file_dict_fname)

def load_upstream_tree():
    # NOTE: Upstream file structure has user's data inside the 'My Drive'
    # directory, things outside of it are created by someone else and shared
    # with the user. Even though we store all upstream file information (to at
    # least detect changes to shared files and ignore them), we asssume
    # 'My Drive' is the root of the upstream tree. Management of shared files
    # is not implemented.
    return pickle_load (upstream_file_tree_fname)['My Drive']

def store_upstream_tree(real_root):
    # CAUTION: Don't pass the root returned by load_upstream_tree()!!!! That's
    # not the REAL upstream root, it's the 'My Drive' directory.
    # TODO: When we get a real intermetiate data structure for file trees, this
    # shuld be hidden by the API. It should be possible to load the upstream
    # tree, modify it, then dump it back again to a file.
    pickle_dump (real_root, upstream_file_tree_fname)

def load_local_tree():
    if path_exists (local_file_tree_fname):
        return pickle_load (local_file_tree_fname)
    else:
        return {'c':{}}

def store_local_tree(root):
    return pickle_dump (root, local_file_tree_fname)


###############################
# File synchronization backend
#
# TODO: Move this into another file. We don't want these functions to be called
# as pymk snips.

def recursive_tree_compare(local, upstream, path_lst=[]):
    missing_upstream = []
    missing_locally = []
    different = []
    checksum_count = 0
    children_count = 0

    # NOTE: Files can be different in 2 ways. Their content may be different
    # (checksum mismatch) or maybe their types are different (type mismatch)
    # and we are trying to compare a file with a directory.
    if 'md5Checksum' in local.keys() and 'md5Checksum' in upstream.keys():
        if local['md5Checksum'] != upstream['md5Checksum']:
            different.append (os.sep.join(path_lst))
        else:
            checksum_count += 1
    elif ('md5Checksum' in local.keys()) != ('md5Checksum' in upstream.keys()):
        different.append (os.sep.join(path_lst))

    if 'c' in local.keys() and 'c' in upstream.keys():
        both = local['c'].keys() & upstream['c'].keys()
        children_count += len(both)
        for fname in both:
            local_f = local['c'][fname]
            upstream_f = upstream['c'][fname]

            l_missing_upstream, l_missing_locally, l_different, l_checksum_count, l_children_count = \
                recursive_tree_compare(local_f, upstream_f, path_lst=path_lst + [fname])
            missing_upstream += l_missing_upstream
            missing_locally += l_missing_locally
            different += l_different
            checksum_count += l_checksum_count
            children_count += l_children_count

        for fname in upstream['c'].keys() - local['c'].keys():
            missing_locally.append(path_cat(os.sep.join(path_lst), fname))

        for fname in local['c'].keys() - upstream['c'].keys():
            missing_upstream.append(path_cat(os.sep.join(path_lst), fname))

    elif 'c' not in local.keys() and 'c' in upstream.keys():
        for fname in upstream['c'].keys():
            missing_locally.append(path_cat(os.sep.join(path_lst), fname))

    elif 'c' in local.keys() and 'c' not in upstream.keys():
        for fname in local['c'].keys():
            missing_upstream.append(path_cat(os.sep.join(path_lst), fname))

    return missing_upstream, missing_locally, different, checksum_count, children_count

class SubtreeDiff():
    def __init__(self, local_path, remote_path):
        self.local_path = local_path
        self.remote_path = remote_path

        self.bound_subtrees = set()
        self.local_missing = []
        self.remote_missing = []
        self.different = []

        # TODO: Clean this up, I'm not sure this, it should probably move to
        # the test suite and leave a simpler equality verification during
        # normal operation. Also, the skip_subtrees set doesn't really work in
        # all cases, need to implement an algorithm that handles all cases. To
        # make it easier, first abstract things out so we can have a proper
        # test suite.
        self.is_equal = False
        self.skip_subtrees = set()
        self.equal_checksums = 0
        self.equal_node_names = 0
        self.upstream_file_count = 0
        self.upstream_children_count = 0
        self.local_file_count = 0
        self.local_children_count = 0

def compute_diff(local_tree, remote_tree, bindings):
    """
    Computes what has changed between the local and upstream trees, taking into
    account the passed bindings.
    """
    
    diff_result = []

    to_remove = set()
    is_first = True
    for upstream_path, local_path in bindings.items():
        subtree_diff = SubtreeDiff(local_path, upstream_path)

        local_subtree = lookup_path (local_tree, path_as_list(local_path))
        upstream_subtree = lookup_path (remote_tree, path_as_list(upstream_path))

        missing_upstream, tmp_missing_locally, different, checksum_count, children_count = \
            recursive_tree_compare(local_subtree, upstream_subtree)

        subtree_diff.different = different
        subtree_diff.remote_missing = missing_upstream
        subtree_diff.equal_checksums = checksum_count
        subtree_diff.equal_node_names = children_count

        # Bound directories will be counted as missing locally on the root
        # comparison, here we remove those from the actual list of files missing
        # upstream.
        for fpath in tmp_missing_locally:
            # TODO: When we support binding files upstream, we shouldn't force
            # the upstream path to be terminated by '/'.
            upstream_fpath = path_cat(upstream_path, fpath, '')

            # Consider the case where we have the following bindings:
            #
            #   L:/home/user/Drive/   -> U:/
            #   L:/home/user/datadir1 -> U:/MyData/datadir1
            #   L:/home/user/datadir2 -> U:/MyData/datadir2
            #
            # Now let's assume L:/home/user/Drive/ is empty. When comparing
            # the first binding's subtrees, L:/home/user/Drive/MyDrive will
            # be reported as missing. Although U:/MyData isn't bound
            # directly, we have 2 bindings that have U:/MyData as ancestor.
            #
            # The following code detects those bindings and adds
            # U:/MyData/datadir1 and U:/MyData/datadir2 to the bound
            # subtrees set (only for reporting purposes). At the same time,
            # it adds U:/MyData to a different set, so verify_diff ()
            # discounts the size of this subtree when verifying the number
            # of comparisons made.
            upstream_bindings = []
            for binding_upstream in bindings.keys():
                if binding_upstream.startswith(upstream_fpath):
                    upstream_bindings.append(binding_upstream)

            if len(upstream_bindings) == 0:
                subtree_diff.local_missing.append (fpath)
            else:
                subtree_diff.bound_subtrees.update (upstream_bindings)
                subtree_diff.skip_subtrees.add (canonical_path(upstream_fpath))

        verify_diff (subtree_diff, checksum_count, children_count, upstream_subtree, local_subtree, bound_roots=subtree_diff.skip_subtrees)
        diff_result.append (subtree_diff)

    return diff_result

def compute_push (local_tree, upstream_tree):
    """
    Computes the actions necessary to make bound trees upstream be updated to
    the state of their local counterparts (we call this a push). For instance,
    any locally removed files will be permanently removed upstream. Same will
    happen for new files or file changes.

    Returns a tuple of 3 data structures:

        to_upload: Map from local paths to the upstream path where they should
          be created new.

        to_update: Map from local paths to their existing upstream version that
          needs to be updated.

        to_remove: Set of upstream paths to be removed.
    """

    to_upload = {}
    to_update = {}
    to_remove = set()

    bindings = store_get(bindings_prop)
    diff_results = compute_diff (local_tree, upstream_tree, bindings)

    for diff_result in diff_results:
        local_path = diff_result.local_path
        remote_path = diff_result.remote_path

        for fpath in diff_result.different:
            to_update[f'{path_cat(local_path, fpath)}'] = f'{path_cat(remote_path, fpath)}'

        for fpath in diff_result.remote_missing:
            to_upload[f'{path_cat(local_path, fpath)}'] = f'{path_cat(remote_path, fpath)}'

        for fpath in diff_result.local_missing:
            to_remove.add(f'{path_cat(remote_path, fpath)}')

    return to_upload, to_update, to_remove


def default ():
    target = store_get ('last_snip', default='example_procedure')
    call_user_function(target)

def set_upstream_file_entry(file_dict, file_resource):
    file_resource['_internal_modifiedTime'] = dateutil.parser.parse(file_resource['modifiedTime'])
    file_dict[file_resource['id']] = file_resource

def get_file_path(file_dict, node):
    error = False
    path = []
    while not is_root_node(node):
        path.append(node['name'])

        # Advance to first parent. This will only return "a" path, but in Drive
        # a file can have multiple of them.
        if 'parents' in node.keys() and node['parents'][0] in file_dict.keys():
            node = file_dict[node['parents'][0]]
        else:
            if not is_root_node(node):
                error = True
            break

    if not error:
        path.reverse()
        ret = os.sep + os.sep.join(path)
    else:
        ret = None
    return ret

def get_ghost_files(file_dict):
    # For some reason, the sequential file dump still misses some parents. Here
    # we iterate the dump and check that all parent IDs are resolved. I even
    # tried setting to true 'includeItemsFromAllDrives' and
    # 'supportsAllDrives', it didn't work.
    #
    # Looks like the problem happens when permanently removig directories.
    # The subtree for it isn't deleted immediately, so it's possible to get
    # a full dump and still have elements that shouldn't be there anymore.
    ghost_files = {}
    for f_id, f in file_dict.items():
        if 'parents' in f.keys():
            for parent_id in f['parents']:
                if parent_id not in file_dict.keys() and parent_id not in file_dict.keys():
                    ghost_files[parent_id] = f_id

    # Get data of all ghost files and their ancestors
    #
    # TODO: Maybe these files should be specially marked, like "ghost" files?.
    for f_id, child in ghost_files.items():
        try:
            f = google.get(f'https://www.googleapis.com/drive/v3/files/{f_id}')
        except:
            print ('Failed to get parent file {f_id}')
            # TODO: Maybe if this happens, the correct solution is
            # to remove the parent reference from the file, so the
            # tree can be built "normally"?. It's possible we will
            # end up adding stuff to the root that's not supposed
            # to be there...

        if f != None:
            file_dict[f_id] = f
            if 'parents' in f.keys():
                for parent_id in f['parents']:
                    if parent_id not in file_dict.keys() and parent_id not in ghost_files:
                        ghost_files.add(parent_id)
            print (f'Added ghost file {f_id}')

        else:
            print (f'Failed to get parent {f_id} of {ghost_files[f_id]}')


def sequential_file_dump ():
    """
    This requests all file information from google drive and dumps it into a
    file representing a dictionary indexed by id. It gets enough information
    for us to compare the upstream file with one downstream.
    """

    restart = get_cli_bool_opt('--restart')
    progress_flag_name = 'sequentialTraversalInProgress'
    is_in_progress = store_get(progress_flag_name, default=False) and not restart

    parameters = {'fields':'nextPageToken,files(id,mimeType,modifiedTime,name,md5Checksum,parents)', 'pageSize':1000, 'q':'trashed = false'}

    success = False
    files = {}
    if is_in_progress:
        print ('Detected partially complete dump, restarting using stored page token.')
        parameters['pageToken'] = store_get('nextPageToken')
        files = load_upstream_file_dict()

    while True:
        try:
            json_data = google.get('https://www.googleapis.com/drive/v3/files', params=parameters)
        except Exception as e:
            print ('Error while performing request to Google, dump can be restarted by re running the command.')
            print (traceback.format_exc())
            store(progress_flag_name, True)
            break

        if json_data != None:
            if 'files' in json_data.keys():
                for f in json_data['files']:
                    f_id = f['id']
                    if f_id in files:
                        # This should never happen
                        print (f'Found repeated ID {f_id}')
                    set_upstream_file_entry(files, f)

                print (f'Received: {len(json_data["files"])} ({json_data["files"][-1]["id"] if len(files) > 0 else ""})')
            else:
                print (f'Received response without files.')
                print (json_data)

            if 'nextPageToken' not in json_data.keys():
                # Successfully reached the end of the full file list
                store(progress_flag_name, False)
                success = True
                break
            else:
                nextPage_token = json_data['nextPageToken']
                store('nextPageToken', nextPage_token)
                parameters['pageToken'] = nextPage_token

    if success:
        # Get last change token
        change_token = None
        while change_token is None:
            try:
                change_token = google.get('https://www.googleapis.com/drive/v3/changes/startPageToken')
            except Exception as e:
                change_token = None
                print ('Error while getting changes token.')
                print (traceback.format_exc())
                break
        store (changes_token_prop, change_token['startPageToken'])

        get_ghost_files(files)

    store_upstream_file_dict (files)
    print (f'Total: {len(files)}')

def tree_file_dump ():
    parameters = {'fields':'nextPageToken,files(id,mimeType,name,md5Checksum,parents)', 'pageSize':1000, 'q':"'root' in parents"}

    # TODO: Implement this. The idea is to have a tree based traversal of
    # google drive. This traversal would be more useful for partial exploration
    # of the file tree. The tricky part of doing this, will be handling a
    # failed request, because we need to keep the partial state from before, in
    # order to resume the tree traversal from the same place where we left.

    files = {}

    store_upstream_file_dict (files)
    print (f'Total: {len(files)}')

def recursive_tree_print(node, indent=''):
    print (indent + node['name'])
    if 'c' in node.keys():
        for child in node['c']:
            recursive_tree_print(child, indent=indent + ' ')

def recursive_path_tree_print(node, path='', depth=None):
    if not is_root_node(node):
        print (path_cat(path, node['name']))
        next_path = path_cat(path, node['name'])
    else:
        next_path = '/'

    if 'c' in node.keys() and (depth==None or depth > 0):
        if depth != None:
            depth = depth-1

        for name, child in node['c'].items():
            recursive_path_tree_print(child, path=next_path, depth=depth)

def print_tree_cmd(tree):
    depth = get_cli_arg_opt ('--depth')
    if depth != None:
        depth = int(depth)

    path = None
    rest_cli = get_cli_no_opt()
    if rest_cli != None:
        path = rest_cli[0]

    upstream_tree = tree
    node = upstream_tree
    if path != None:
        node = lookup_path_subtree (upstream_tree, path_as_list(path))

    recursive_path_tree_print (node, depth=depth)

def print_upstream_tree():
    print_tree_cmd (load_upstream_tree())

def print_local_tree():
    print_tree_cmd (load_local_tree())

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

def tree_new_child(parent, child_id, child_name):
    new_child = {'id': child_id, 'name': child_name}
    tree_set_child (parent, new_child)
    return new_child

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
    file_dict = load_upstream_file_dict()

    root = {}
    for f_id, f in file_dict.items():
        # Ensure all directories have a children dictionary, even if it's
        # empty. Currently when computing the diff we distinguish between files
        # and directories by the presence/abscence of this value.
        if 'mimeType' in f.keys() and f['mimeType'] == "application/vnd.google-apps.folder" and 'c' not in f.keys():
            f['c'] = {}

        if 'parents' in f.keys():
            for parent_id in f['parents']:
                if parent_id in file_dict.keys():
                    tree_set_child (file_dict[parent_id], f)
        else:
            root[f['name']] = f

    store_upstream_tree(root)

def lookup_path (root, path_lst, silent=False):
    curr_path = ''
    node = root
    for dirname in path_lst:
        curr_path = path_cat(curr_path, dirname)
        if 'c' in node.keys() and dirname in node['c'].keys():
            node = node['c'][dirname]
        else:
            node = None
            if not silent:
                print (f"File doesn't exist: {curr_path}")
            break
    return node

def lookup_path_subtree (node, path_lst):
    """
    By definition root node doesn't have a name, when iterating from a root
    node path_lst[0] is a child of the unamed root. When starting from an
    arbitrary subtree, path_lst[0] should match the name of the passed node.
    This function handles both cases.
    """

    curr_path = ''
    not_found = False
    result = None

    if is_root_node(node):
        result = lookup_path(node, path_lst)
    elif path_lst[0] == node['name']:
        result = lookup_path(node, path_lst[1:])
    else:
        print (f"File doesn't exist: {path_lst[0]}")

    return result

def path_as_list(path):
    # This is uglier than I wanted because, oddly enough
    #       ''.split(' ') returns ['']
    # but
    #       ''.split() returns []
    # why?...
    #
    # This means "/".strip(os.sep) returns [''] not [], so we handle it as a separate case.
    return [] if path.strip(os.sep).strip() == '' else path.strip(os.sep).split(os.sep)

def recursive_name_duplicates_print_collect_removal(path, node, to_remove, sequential_file_dump):
    if 'duplicateNames' in node.keys():
        duplicate_ids = {id for id in node['duplicateNames']}
        duplicate_ids.add(node['id'])

        all_equal = True
        oldest_id = node['id']
        for id in duplicate_ids:
            if sequential_file_dump[id]['_internal_modifiedTime'] < sequential_file_dump[oldest_id]['_internal_modifiedTime']:
                oldest_id = id

            if is_file_node(sequential_file_dump[id]) and is_file_node(sequential_file_dump[oldest_id]):
                if 'md5Checksum' not in sequential_file_dump[id] or 'md5Checksum' not in sequential_file_dump[oldest_id]:
                    # NOTE: I've seen duplicates of files that don't have a
                    # checksum. As far as I've seen, it only happens with
                    # Google Apps documents (Google Docs, Sheets etc.).
                    all_equal = False

                elif sequential_file_dump[id]['md5Checksum'] != sequential_file_dump[oldest_id]['md5Checksum']:
                    all_equal = False

            elif is_dir_node(sequential_file_dump[id]) and is_dir_node(sequential_file_dump[oldest_id]):
                # TODO: We need a unified file tree structure that allows
                # indexing by ID and getting all children. Then we should be
                # able to compare the name-named directories with code like the
                # one below. Then we can be sure it's safe to delete them. For
                # now, just warn that this may not be safe.
                all_equal = False

                #missing_2, missing_1, different, checksum_count, children_count = \
                #    recursive_tree_compare(sequential_file_dump[id], sequential_file_dump[oldest_id])
                #if len(missing_1) + len(missing_2) + len(different) > 0:
                #    all_equal = False
            else:
                all_equal = False

        duplicate_ids.remove(oldest_id)
        to_remove[(path, oldest_id, all_equal)] = duplicate_ids

    if 'c' in node.keys():
        for name, child in node['c'].items():
            recursive_name_duplicates_print_collect_removal(path_cat(path, name), child, to_remove, sequential_file_dump)

def recursive_name_duplicates_print(path, node):
    if 'duplicateNames' in node.keys():
        print (path)

    if 'c' in node.keys():
        for name, child in node['c'].items():
            recursive_name_duplicates_print(path_cat(path, name), child)

def show_name_duplicates():
    """
    Receives an upstream path of a subtree and prints all distinct upstream
    files with duplicate names.
    """
    path = '/'
    if len(sys.argv) > 2:
        path = sys.argv[2]
    path_lst = path_as_list(path)

    node = lookup_path (load_upstream_tree(), path_lst)
    recursive_name_duplicates_print(path, node)

def remove_name_duplicates():
    """
    Receives an upstream path of a subtree and removes all distinct upstream
    files with duplicate names. It keeps the oldest version of a file.

    Pass --dry-run to get a list of what would be deleted without actually doing so.
    """
    is_dry_run = get_cli_bool_opt('--dry-run')

    path = '/'
    rest_cli = get_cli_no_opt()
    if rest_cli != None:
        path = rest_cli[0]
    path_lst = path_as_list(path)

    file_name_tree = load_upstream_tree()
    node = lookup_path (file_name_tree, path_lst)

    file_dict = load_upstream_file_dict()
    to_remove = {}
    recursive_name_duplicates_print_collect_removal(path, node, to_remove, file_dict)

    is_first = True
    service = google.get_service()
    for (path, kept_id, all_equal), removed_ids in to_remove.items():
        if not is_first:
            print()
        else:
            is_first = False

        equality = ecma_yellow('DIFFERENT')
        if all_equal:
            equality = ecma_green('EQUAL')

        print (f"{equality}")
        info (f"R '{path}'")
        print (f"Keeping '{kept_id}'")
        for file_id in removed_ids:
            if not is_dry_run:
                remove_file_id (service, file_id)
            print (f"D {file_id}")

    # TODO: Update upstream tree

def set_file_entry(node_children, abs_path, fname=None, f_stat=None, status=None):
    if f_stat == None:
        f_stat = os.stat(abs_path)

    if fname == None:
        fname = path_basename(abs_path)

    success = False
    if stat.S_ISREG(f_stat.st_mode):
        if abs_path != local_file_tree_fname:
            hash_md5 = hashlib.md5()
            with open(abs_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)

            modified_timestamp = datetime.fromtimestamp(f_stat.st_mtime, timezone.utc)
            checksum = hash_md5.hexdigest()
            node_children[fname] = {'name':fname, 'md5Checksum':checksum, '_internal_modifiedTime':modified_timestamp}
            success = True


        else:
            # It's not possible to synchronize upstream the file that stores
            # the local file cache. If we did we would enter an infinite loop
            # where this file is always outdated. Currently with the CLI
            # interface that only means this file will always show as having
            # changed, but if we implement a server that triggers updates on
            # file changes, this would lock it in an infinite cycle.
            log_warning (status, f'Skipping local file tree cache: {abs_path}')

    else:
        log_warning (status, f'Skipping unknown file type (link?): {abs_path}', echo=True)

    return success

def ensure_tree_dirpath (path_lst, node):
    assert is_dir_node(node), "Passing non directory root to ensure_tree_dirpath()"

    created = []
    for i, dirname in enumerate(path_lst):
        if dirname not in node['c'].keys():
            node['c'][dirname] = {'name':dirname, 'c':{}}
            created.append(os.sep + "/".join(path_lst[:i+1]))
        node = node['c'][dirname]

    return node, created

def get_local_file_tree(path, local_file_name_tree = {}, status=None):
    # TODO: I thought I could change local_file_name_tree for a node which we
    # assume is the one pointed to by path.It would've made things faster
    # because we won't be ensuring the whole path exists in each directory
    # iteration.
    #
    # I now think it's not that simple. In some cases, for example if a new
    # binding was added that points to local path that hasn't been explored, we
    # need to ensure all ancestors exist before we can get a node from which to
    # start adding the rest of the tree, and we have to attach these ancestors
    # to the last existing parent in the tree. This means we must always have a
    # reference to the root from which to start finding the common ancestor.
    # The good news it I think this only needs to be done at the start of this,
    # before we start the directory traversal, so we could still get the better
    # performance. As long as os.walk guarantees dirpath increases at most 1
    # level each iteration.
    if not os.path.isdir(path):
        print (f"Trying to traverse something that isn't a directory: {path}")
        return

    path_lst = []
    for dirpath, dirnames, filenames in os.walk(path):
        for dname in dirnames:
            # Symlinks to directories are not followed by os.walk() by default,
            # but they do show inside dirnames, we just notify the user they
            # are being ignored.
            fpath = path_cat (dirpath, dname)
            if os.path.islink(fpath):
                log_warning (status, f'Ignoring link to directory {path_cat(fpath)}')

        path_lst = path_as_list(dirpath)
        # This should print whenever a directory is created
        node, created_dirs = ensure_tree_dirpath (path_lst, local_file_name_tree)
        for created_dir in sorted(created_dirs):
            print (f'A {path_cat(created_dir,"")}')

        for fname in filenames:
            abs_path = path_cat(dirpath, fname)
            if set_file_entry (node['c'], path_cat(dirpath, fname), fname=fname, status=status):
                print (f'A {node["c"][fname]["md5Checksum"]} - {path_cat(dirpath, fname)}')

    return local_file_name_tree

def set_3_way_operate(set1, set2):
    # TODO: This feels slow, is it?, or does Python keep some cache that makes
    # these operations fast?.
    return set1-set2, set1&set2, set2-set1;


def build_local_file_name_tree():
    status = Status()

    if len(sys.argv) > 3:
        path = sys.argv[2]
        path = os.path.abspath(path_resolve(path))
        out_path = sys.argv[3]

        local_file_name_tree = get_local_file_tree(path, status=status)
        pickle_dump (local_file_name_tree, out_path)

    else:
        local_file_name_tree = {}
        for upstream_path, local_path in store_get(bindings_prop).items():
            info (f"L '{local_path}'")
            get_local_file_tree (local_path, local_file_name_tree=local_file_name_tree, status=status)

        store_local_tree (local_file_name_tree)

    print()
    status.print()

def recursive_update_local_file_tree(path_lst, node, local_file_name_tree, status=None):
    abs_path = os.sep + os.sep.join(path_lst)

    if 'c' in node.keys():
        new_dirs = set()
        new_files = set()
        new_entries = {}
        for dir_entry in os.scandir(abs_path):
            new_entries[dir_entry.name] = dir_entry
            if dir_entry.is_dir(follow_symlinks=False):
                new_dirs.add(dir_entry.name)
            elif dir_entry.is_file():
                new_files.add(dir_entry.name)

        old_dirs = set()
        old_files = set()
        old_nodes = node['c']
        for name, child in node['c'].items():
            if 'c' in child.keys():
                old_dirs.add(name)
            else:
                old_files.add(name)

        removed_dirs, equal_dirs, added_dirs = set_3_way_operate(old_dirs, new_dirs)
        removed_files, equal_files, added_files = set_3_way_operate(old_files, new_files)

        for removed in removed_dirs:
            del old_nodes[removed]
            print (f'D {path_cat(abs_path, removed)}')

        for removed in removed_files:
            del old_nodes[removed]
            print (f'D {path_cat(abs_path, removed)}')

        for dirname in equal_dirs:
            recursive_update_local_file_tree(path_lst + [dirname], old_nodes[dirname], local_file_name_tree)

        for fname in equal_files:
            f_stat = new_entries[fname].stat()
            modified_timestamp = datetime.fromtimestamp(f_stat.st_mtime, timezone.utc)
            if modified_timestamp > old_nodes[fname]['_internal_modifiedTime']:
                fpath = path_cat(abs_path, fname)
                old_md5 = old_nodes[fname]['md5Checksum']
                if set_file_entry(old_nodes, fpath, fname=fname, f_stat=f_stat, status=status):
                    print (f'U {old_md5} -> {old_nodes[fname]["md5Checksum"]} - {fpath}')

        for fname in added_dirs:
            get_local_file_tree (path_cat(abs_path, fname), local_file_name_tree, status=status)

        for fname in added_files:
            fpath = path_cat(abs_path, fname)
            if set_file_entry(old_nodes, fpath, status=status):
                print (f'A {old_nodes[fname]["md5Checksum"]} - {fpath}')

def get_file_by_id():
    if len(sys.argv) > 2:
        f_id = sys.argv[2]
    else:
        print ('Missing arguments.')
        return

    file_dict = load_upstream_file_dict()
    if f_id in file_dict.keys():
        f = file_dict[f_id]
        if is_root_node(f):
            print ('(root)')
        for attr in f.keys():
            print (f'{attr}: {f[attr]}')
    else:
        print ('File id not found: {f_id}')


def update_upstream_file_name_tree():
    print ('Updating remote index...')

    # TODO: Test these cases:
    #  - What happens when thrashing/removing a subtree?, I would guess we get
    #    a change object for each folder/file in it.
    #  - What happens when files/subtrees are moved?.


    #  Information of permanently removed files can't be accessed anymore, so
    #  the 'file' attribute of the change object won't be present. The id of
    #  the removed file will come in the 'fileId' attribute of the change
    #  object. This will happen for example when the trash bin is emptied.
    #
    #  This is why we don't filter out thrashed files here, like we do in
    #  sequential_file_dump().
    parameters = {'fields':'newStartPageToken,nextPageToken,changes(fileId,changeType,removed,file(id,name,mimeType,modifiedTime,md5Checksum,parents,trashed))', 'pageSize':1000}
    parameters['pageToken'] = store_get(changes_token_prop)

    changed = False
    file_dict = load_upstream_file_dict()
    file_dict_old = file_dict.copy()

    while True:
        try:
            json_data = google.get('https://www.googleapis.com/drive/v3/changes', params=parameters)
        except Exception as e:
            print ('Error while performing request to Google, dump can be restarted by re running the command.')
            print (traceback.format_exc())
            store(progress_flag_name, True)
            break

        if json_data != None:
            changes = json_data['changes']

            while 'nextPageToken' in json_data.keys():
                parameters['pageToken'] = json_data['nextPageToken']
                try:
                    json_data = google.get('https://www.googleapis.com/drive/v3/changes', params=parameters)
                    changes += json_data['changes']
                except Exception as e:
                    print ('Error while performing request to Google, dump can be restarted by re running the command.')
                    print (traceback.format_exc())
                    store(progress_flag_name, True)
                    break

            next_token = json_data['newStartPageToken']
            parameters['pageToken'] = next_token

            if len(changes) > 0:
                changed = True
                for change in changes:
                    f_id = change["fileId"]

                    # NOTE: Thrashed files are not really removed, they only
                    # get their 'thrashed' attribute set to true.
                    if change['removed'] or ('file' in change.keys() and change['file']['trashed']):
                        if f_id in file_dict_old.keys():
                            path = get_file_path(file_dict_old, file_dict_old[f_id])

                            # This can happen when deleting a directory, we
                            # first get the update of the directory removal and
                            # we remove the whole subtree in the local index.
                            # Then Drive takes some time to create update
                            # events for the content of the directory which we
                            # get later, but those file nodes were already
                            # remove from the upstream index.
                            #
                            # TODO: A better approach could be to track these
                            # removed but pending-to-be-notified-by-Drive
                            # nodes. Then we can be sure all non found IDs are
                            # only those we expected. Otherwise we should
                            # report an error.
                            if path == None:
                                path = f_id
                        else:
                            path = change

                        if f_id in file_dict.keys():
                            del file_dict[f_id]
                            print(f'D {path}')
                        else:
                            # Got a change that represents a deletion but we
                            # didn't have a record of that file before. This
                            # can happen if a user creates a file then deletes
                            # it, but we didn't do an update between
                            # creation/deletion.
                            #
                            # TODO: For now I print this because it can show
                            # errors in the change processing logic, but really
                            # users shouldn't care about this if we are sure it
                            # only happens in the case described above.
                            print(f'D? {path}')

                    elif 'file' in change.keys():
                        f = change['file']
                        set_upstream_file_entry (file_dict, f)
                        path = get_file_path(file_dict, file_dict[f_id])

                        if path != None:
                            if f_id in file_dict_old.keys():
                                if 'md5Checksum' not in f.keys():
                                    print(f'U {path}')
                                else:
                                    old_hash = file_dict_old[f_id].get('md5Checksum')
                                    print(f'U {old_hash} -> {f["md5Checksum"]} - {path}')

                            else:
                                if 'md5Checksum' not in f.keys():
                                    print(f'A {path}')
                                else:
                                    print(f'A {f["md5Checksum"]} - {path}')

                        else:
                            # This will happen when a file shared with the user
                            # is updated. These files are outside of the 'My
                            # Drive' directory which is what we conside to be
                            # the upstream root.
                            print (f'? {change}')

                    else:
                        print (f'? {change}')

            else:
                store(changes_token_prop, next_token)
                break

    if changed:
        get_ghost_files(file_dict)
        store_upstream_file_dict (file_dict)
        build_file_name_tree()

def update_local_file_name_tree():
    print ('Updating local index...')
    status = Status()

    local_file_name_tree = load_local_tree()
    for upstream_path, local_path in store_get(bindings_prop).items():
        info (f"L '{local_path}'")
        local_path_lst = path_as_list (local_path)

        binding_root = lookup_path(local_file_name_tree, local_path_lst, silent=True)
        assert binding_root != None
        # :file_bindings would need a separate case.
        recursive_update_local_file_tree (local_path_lst, binding_root, local_file_name_tree, status=status)

    status.print()
    store_local_tree (local_file_name_tree)

def canonical_path(path):
    return os.sep + path.strip(os.sep)

def recursive_tree_size(node, path='', skip=set()):
    count = 0
    file_count = 0
    file_list = []
    if 'c' in node.keys():
        for name, child in node['c'].items():
            c_path = canonical_path(path_cat(path, node['name'], name))
            if c_path not in skip:
                count += 1
                l_count, l_file_count, l_file_list = recursive_tree_size(child, path=path_cat(path, node['name']), skip=skip)
                count += l_count
                file_count += l_file_count
                file_list += l_file_list
    else:
        c_path = canonical_path(path_cat(path, node['name']))
        if c_path not in skip:
            file_list.append(path_cat(path, node['name']))
            file_count += 1
    return count, file_count, file_list

def binding_remove():
    if len(sys.argv) > 2:
        upstream_path = path_cat(sys.argv[2], '')
    else:
        print (f'usage: ./pymk.py {sys._getframe().f_code.co_name} [REMOTE PATH]')
        return

    bindings = store_get(bindings_prop, default={})
    local_path = bindings[upstream_path]
    local_file_name_tree = load_local_tree()

    path_lst = path_as_list(local_path)
    node = lookup_path (local_file_name_tree, path_lst)

    # Remove node from tree and dump updated tree
    parent = lookup_path (local_file_name_tree, path_lst[:-1])
    children = parent['c']
    del children[node['name']]
    store_local_tree (local_file_name_tree)

    del bindings[upstream_path]
    store(bindings_prop, bindings)

def binding_check(bindings, local_path, upstream_path):
    if upstream_path in bindings.keys():
        if local_path == bindings[upstream_path]:
            print (f"Binding already exists: '{local_path}' -> '{upstream_path}'")
        else:
            print (f"Upstream directory already bound: '{upstream_path}'")
        return False
    elif local_path in {local_p for _, local_p in bindings.items()}:
        print (f"Local directory already bound: '{local_path}'")
        return False

    return True

def binding_create_checked(bindings, local_path, upstream_path):
    if binding_check (bindings, local_path, upstream_path):
        bindings[upstream_path] = local_path
        store(bindings_prop, bindings)

def bind_locally_existent(bindings, local_path, upstream_path):
    # Add the parent node of the new binding to the local index
    local_file_name_tree = load_local_tree()
    path_lst = path_as_list(local_path)
    local_tree_node = lookup_path (local_file_name_tree, path_lst, silent=True)
    assert local_tree_node == None, "Local index contains non existent node, it's probably corrupted... this is BAD. Rebuild the local index."
    ensure_tree_dirpath (path_lst, local_file_name_tree)
    store_local_tree (local_file_name_tree)

    binding_create_checked (bindings, local_path, upstream_path)

    update_local_file_name_tree()

def binding_add():
    locally_existent = get_cli_bool_opt ("--downloaded")
    rest_parameters = get_cli_no_opt();
    if rest_parameters != None and len(rest_parameters) == 2:
        # For now bindings can only happen between two directories, there's no
        # way to bind an upstream file into a local directory, this allows
        # having different directory names upstream and locally. Here we make
        # sure stored paths always have a trailing '/'.
        #
        # Another approach would be to always bind an upstream file or
        # directory into a local directory and always take the local directory
        # in the binding as the parent of whatever was selected upstream. This
        # enforces having the same name upstream and locally and allows binding
        # of single files, but the asymetry of the relationship is probably not
        # as intuitive?... not sure.
        #
        # We could also support both, by adding some semantics to the trailing
        # '/', like rsync does. The problem is I never remember rsync's
        # semantics, I don't want that to happen here.
        # :file_bindings
        local_path = path_cat(os.path.abspath(path_resolve(rest_parameters[0])), '')
        upstream_path = path_cat(rest_parameters[1], '')
    else:
        print (f'usage: ./pymk.py {sys._getframe().f_code.co_name} [LOCAL PATH] [REMOTE PATH]')
        return

    # Make sure the binding is new
    # TODO: Implement binding update
    bindings = store_get(bindings_prop, default={})
    if not binding_check (bindings, local_path, upstream_path):
        return

    # The whole code keeps the invariant that binding folders always exist in
    # both local and upstream trees. Here we make sure that's the case so we
    # don't get failures later.
    #
    # NOTE: This means we need to explicitly handle the case of someone
    # restoring their configuration manually. Either we need an explicit
    # "reload_config" command, or everytime a tree cache is loaded we must make
    # sure bound paths exist in the tree.
    upstream_tree = load_upstream_tree()

    # Currently bindings can only be added to upload a directory
    # TODO: Implement binding addition to download directories
    upstream_tree_node = lookup_path (upstream_tree, path_as_list(upstream_path), silent=True)
    if path_exists(local_path) and path_isdir(local_path) and upstream_tree_node == None:
        local_file_name_tree = load_local_tree()

        path_lst = path_as_list(local_path)
        local_tree_node = lookup_path (local_file_name_tree, path_lst, silent=True)
        if local_tree_node == None:
            ensure_tree_dirpath (path_lst, local_file_name_tree)
            store_local_tree (local_file_name_tree)

            service = google.get_service()
            ensure_upstream_dir_path (service, local_path, upstream_tree, upstream_path)

            binding_create_checked (bindings, local_path, upstream_path)

            update_local_file_name_tree()
            update_upstream_file_name_tree()

            # Should we upload the directory here? Right now we don't, user
            # needs to call diff, then push.

        else:
            print ("Invalid binding: local directory is already part of local file tree.")

    elif not path_exists(local_path) and upstream_tree_node != None and is_dir_node(upstream_tree_node):
        # Find out if the directory is bound locally somewhere, in which case
        # we don't need to download anything, we just move it to its new local
        # position, create the binding and update the indices.
        local_parent_path = None
        upstream_parent_path = None
        for binding_upstream, binding_local in bindings.items():
            if upstream_path.startswith(binding_upstream):
                local_parent_path = binding_local
                upstream_parent_path = binding_upstream
                break

        if local_parent_path != None and upstream_parent_path != None:
            local_source = path_cat(local_parent_path, upstream_path.replace(binding_upstream, '', 1))
            shutil.move(local_source, local_path)
            bind_locally_existent (bindings, local_path, upstream_path)

        else:
            print ("Bindings that download subtrees aren't implemented.")

    elif path_exists(local_path) and path_isdir(local_path) and upstream_tree_node != None and is_dir_node(upstream_tree_node):
        if locally_existent:
            bind_locally_existent (bindings, local_path, upstream_path)
        else:
            print ("Bindings that merge subtrees aren't implemented.")

    elif not path_exists(local_path) and upstream_tree_node == None:
        print ("Bindings that create new empty local and upstream directories aren't implemented.")


def binding_show():
    bindings = store_get(bindings_prop)
    if bindings != None:
        for key, value in bindings.items():
            print (f"'{value}' - '{key}'")

def compare_local_dumps():
    if len(sys.argv) == 4:
        tree1 = pickle_load(sys.argv[2])
        tree2 = pickle_load(sys.argv[3])

        missing_2, missing_1, different, checksum_count, children_count = \
            recursive_tree_compare(tree1, tree2)

        for fpath in different:
            print (f'Different: {fpath}')

        for fpath in missing_1:
            print (f'< {fpath}')

        for fpath in missing_2:
            print (f'> {fpath}')

        if len(missing_1) + len(missing_2) + len(different) > 0:
            print ()

        print (f'Successful checksum comparisons: {checksum_count}')
        print (f'Children name comparisons: {children_count}')
        children_count, file_count, *_ = recursive_tree_size(tree1['c']['home'])
        print (f'Tree 1 size: {file_count}/{children_count}')
        children_count, file_count, *_ = recursive_tree_size(tree2['c']['home'])
        print (f'Tree 2 size: {file_count}/{children_count}')

def verify_diff (diff_result, checksum_count, children_count, upstream_subtree, local_subtree, bound_roots=None):
    """
    Reduntant check to make sure things are working correctly. We test that we
    compared the same number of checksums to be equal as the number of files.
    Also check the numper of node name comparisons is equal.
    
    In theory just checking nothing is missing and nothing is different should
    be enough, but we do this in case some bug is causing us not to traverse
    the full tree or something like that. When code is better tested we could
    move this into the test suite and make normal operation faster.
    """

    upstream_children_count, upstream_file_count, *_ = recursive_tree_size(upstream_subtree)
    local_children_count, local_file_count, *_ = recursive_tree_size(local_subtree)

    if bound_roots != None:
        upstream_bound_children_count = 0
        upstream_bound_file_count = 0
        for bound_root in bound_roots:
            upstream_subtree_root = lookup_path_subtree (upstream_subtree, path_as_list(bound_root))
            c_count, f_count, *_ = recursive_tree_size(upstream_subtree_root)
            upstream_bound_children_count += c_count
            upstream_bound_file_count += f_count

        upstream_children_count -= upstream_bound_children_count + len(bound_roots)
        upstream_file_count -= upstream_bound_file_count

    if children_count == upstream_children_count and children_count == local_children_count and \
            checksum_count == upstream_file_count and checksum_count == local_file_count:
        diff_result.is_equal = True

    diff_result.upstream_file_count = upstream_file_count
    diff_result.upstream_children_count = upstream_children_count
    diff_result.local_file_count = local_file_count
    diff_result.local_children_count = local_children_count


def diff():
    # TODO: Update local and upstream trees

    is_verbose = get_cli_bool_opt ('--verbose')

    rest_cli = get_cli_no_opt ()
    if rest_cli != None and len(rest_cli) == 2:
        local_path = os.path.abspath(path_resolve(rest_cli[0]))
        upstream_path = rest_cli[1]

        if get_cli_bool_opt('--build-local'):
            local_tree = get_local_file_tree(local_path)
            print()
        else:
            local_tree = load_local_tree()
        local_path_lst = path_as_list(local_path)
        local_subtree = lookup_path (local_tree, local_path_lst)

        upstream_tree = load_upstream_tree()
        upstream_path_lst = path_as_list(upstream_path)
        upstream_subtree = lookup_path (upstream_tree, upstream_path_lst)

        subtree_diff = SubtreeDiff(local_path, upstream_path)

        missing_upstream, missing_locally, different, checksum_count, children_count = \
            recursive_tree_compare(local_subtree, upstream_subtree)

        subtree_diff.equal_checksums = checksum_count
        subtree_diff.equal_node_names = children_count
        subtree_diff.remote_missing = missing_upstream
        subtree_diff.local_missing = missing_locally
        subtree_diff.different = different

        verify_diff (subtree_diff, checksum_count, children_count, upstream_subtree, local_subtree)
        diff_results = [subtree_diff]

        # TODO: Handle the case where the path being compared contains a bound
        # subtree. Right now it will show them as being different even if they
        # aren't because we assume the content of bound subtrees is missing.
        # Should we warn about this? or convert this diff operation into a
        # binding aware one that uses compute_diff()?

    elif rest_cli == None:
        local_tree = load_local_tree()
        upstream_tree = load_upstream_tree()
        bindings = store_get(bindings_prop)

        diff_results = compute_diff (local_tree, upstream_tree, bindings)

    else:
        print ('Invalid arguments.')
        return

    is_first = True
    for diff_result in diff_results:
        if not diff_result.is_equal or is_verbose:
            local_path = diff_result.local_path
            remote_path = diff_result.remote_path

            if not is_first:
                print()
            is_first = False

            if is_verbose:
                equality = ecma_yellow('DIFFERENT')
                if diff_result.is_equal:
                    equality = ecma_green('EQUAL')
                print (f"{equality}")

            info (f"L '{local_path}'")
            info (f"R '{remote_path}'")

            for bound_subtree in sorted(diff_result.bound_subtrees):
                print (ecma_cyan(f'B {bound_subtree}'))

            for fpath in diff_result.different:
                print (f'!= {fpath}')

            for fpath in diff_result.local_missing:
                print (f'-L {fpath}')

            for fpath in diff_result.remote_missing:
                print (f'-R {fpath}')

            if not diff_result.is_equal:
                print ()

            print (f'Comparison count:    {diff_result.equal_checksums}/{diff_result.equal_node_names}')
            print (f'Remote subtree size: {diff_result.upstream_file_count}/{diff_result.upstream_children_count}')
            print (f'Local subtree size:  {diff_result.local_file_count}/{diff_result.local_children_count}')

def is_file_node(node):
    ret = 'c' not in node.keys()
    if 'mimeType' in node.keys():
        ret = node['mimeType'] != 'application/vnd.google-apps.folder'
    return ret

def is_dir_node(node):
    ret = 'c' in node.keys()
    if 'mimeType' in node.keys():
        ret = node['mimeType'] == 'application/vnd.google-apps.folder'
    return ret

def is_root_node(node):
    return ('name' in node.keys() and node['name'] == 'My Drive') or 'name' not in node.keys()

def remove_file(service, upstream_root, upstream_abs_path, status=None):
    # Find file in upstream tree
    path_lst = path_as_list(upstream_abs_path)
    path_node = lookup_path (upstream_root, path_lst)

    if path_node != None:
        remove_file_id (service, path_node['id'])
        print (f"D {upstream_abs_path}")
    else:
        log_error (status, f"File deletion failed: {upstream_abs_path}")

def remove_file_id(service, file_id):
    request = service.files().delete(fileId=file_id).execute()

def upload_file(service, local_abs_path, upstream_root, upstream_abs_path, status=None):
    if not os.path.isfile(local_abs_path):
        log_error (status, f"Can't upload because it's not a file: {local_abs_path}")
        return

    # Find parent in upstream tree
    path_lst = path_as_list(upstream_abs_path)
    directory_path = path_lst[:-1]
    parent_node = lookup_path (upstream_root, directory_path)

    if parent_node != None:
        file_metadata = {'name': path_lst[-1], 'parents': [parent_node['id']]}
        data = MediaFileUpload(local_abs_path,
                mimetype=mimetypes.MimeTypes().guess_type(path_lst[-1])[0],
                resumable=True,
                chunksize=1048576)

        print (f"A {local_abs_path} -> {upstream_abs_path}")

        if data.size() > 0:
            request = service.files().create(body=file_metadata, media_body=data)
            google.request_execute_cli(request)

        else:
            log_error (status, f"File upload failed, local file contains no data: {local_abs_path}")

    else:
        log_error (status, f"File upload failed, directory '{dirname}' doesn't exist upstream: {upstream_abs_path}")

def update_file(service, local_abs_path, upstream_root, upstream_abs_path, status=None):
    if not os.path.isfile(local_abs_path):
        log_error (status, f"Can't update because it's not a file: {local_abs_path}")
        return

    # Find file in upstream tree
    path_lst = path_as_list(upstream_abs_path)
    path_node = lookup_path (upstream_root, path_lst)

    if is_file_node(path_node) and path_node != None:
        data = MediaFileUpload(local_abs_path,
                mimetype=mimetypes.MimeTypes().guess_type(path_lst[-1])[0],
                resumable=True,
                chunksize=1048576)

        print (f"U {local_abs_path} -> {upstream_abs_path}")

        request = service.files().update(fileId=path_node['id'], media_body=data)
        google.request_execute_cli(request)

    else:
        log_error (status, f"File update failed: {upstream_abs_path}")

def ensure_upstream_dir_path(service, local_abs_path, upstream_root, upstream_abs_path):
    if not os.path.isdir(local_abs_path):
        print (f"Failed to create directory upstream, because it's not a directory locally: {local_abs_path}")
        return

    # Follow upstream tree until we find something that doesn't exist.
    path_lst = path_as_list(upstream_abs_path)
    node = upstream_root
    missing_directory = False
    missing_idx = 0

    for i, dirname in enumerate(path_lst):
        if 'c' in node.keys() and dirname in node['c'].keys():
            node = node['c'][dirname]
        else:
            missing_directory = True
            missing_idx = i
            break

    # Create missing directories
    parent_lst = [node['id']]
    if missing_directory:
        for dir_name in path_lst[missing_idx:]:
            metadata = {
                'name': dir_name,
                'parents': parent_lst,
                'mimeType': 'application/vnd.google-apps.folder'
            }
            create_folder = service.files().create(body=metadata,
                                                   fields='id').execute()
            node = tree_new_child (node, create_folder.get('id', []), dir_name)
            parent_lst[0] = node['id']
        print (f"A {path_cat(upstream_abs_path, '')}")

def upload_path (local_abs_path, upstream_abs_path, service=None, upstream_root=None, status=None):
    """
    Uploads ether a file or a directory recursively
    """

    if service == None:
        service = google.get_service()

    if upstream_root == None:
        upstream_root = load_upstream_tree()

    if os.path.isfile(local_abs_path):
        upload_file (service, local_abs_path, upstream_root, upstream_abs_path)

    elif os.path.isdir(local_abs_path):
        for dirpath, dirnames, filenames in os.walk(local_abs_path):
            for dname in dirnames:
                fpath = path_cat (dirpath, dname)
                if os.path.islink(fpath):
                    log_warning (status, f'Ignoring link to directory {path_cat(fpath)}', echo=True)

            if dirpath.find(local_abs_path) == 0:
                upstream_base = dirpath[len(local_abs_path):]

                upstream_dirpath = path_cat (upstream_abs_path, upstream_base)
                ensure_upstream_dir_path (service, dirpath, upstream_root, upstream_dirpath)

                for fname in filenames:
                    upstream_file_path = path_cat (upstream_dirpath, fname)
                    upload_file (service, path_cat(dirpath, fname), upstream_root, upstream_file_path, status=status)

            else:
                log_error (status, f"Can't create upstream path for: {dirpath} (local: {local_abs_path})", echo=True)

    else:
        log_warning (status, f'Skipping unknown file type (link?): {local_abs_path}', echo=True)

def upload():
    # TODO: This is now useless, a useful version would take a local path and
    # an upstream path as arguments and perform that upload. I have to think
    # how this interacts with bindings, at the beginning I'm thinking I will
    # forbid uploading into bound subtrees, untill we get a "sync"
    # functionality that will download what was uploaded into the locally bound
    # subtree. In any case, we should warn users that they may now have the
    # uploaded files in 2 places, inside the local binding and the place where
    # they originally uploaded it from.

    #if len(to_upload) > 0:
    #    upstream_root = load_upstream_tree()

    #    status = Status()
    #    service = google.get_service()
    #    for local_abs_path, upstream_abs_path in to_upload.items():
    #        upload_path (local_abs_path, upstream_abs_path, service=service, upstream_root=upstream_root, status=status)

    #    # Because the output can be very long, summarize all messages at
    #    # the end
    #    status.print()

    #else:
    #    print ('List of files to upload is empty.')
    print ("Upload isn't used now, use 'push'")

def push():
    # TODO: Make this process less verbose.
    update_local_file_name_tree()
    print()

    update_upstream_file_name_tree()
    print()

    print ('Performing changes in remote...')
    status = Status()
    # TODO: Don't reload trees here, we loaded them before to be able to
    # update them, the update functions should return the updated tree.
    upstream_tree = load_upstream_tree()
    local_tree = load_local_tree ()
    to_upload, to_update, to_remove = compute_push (local_tree, upstream_tree)

    if len(to_upload) > 0 or len(to_update) > 0 or len(to_remove) > 0:
        service = google.get_service()

        if len(to_upload) > 0:
            for local_abs_path, upstream_abs_path in to_upload.items():
                upload_path (local_abs_path, upstream_abs_path, service=service, upstream_root=upstream_tree, status=status)

        if len(to_update) > 0:
            for local_abs_path, upstream_abs_path in to_update.items():
                update_file (service, local_abs_path, upstream_tree, upstream_abs_path, status=status)

        if len(to_remove) > 0:
            for upstream_abs_path in to_remove:
                remove_file (service, upstream_tree, upstream_abs_path, status=status)

        print()

        update_upstream_file_name_tree()

    # Print messages if there are any
    status.print()

def download_and_bind():
    rest_parameters = get_cli_no_opt();
    if rest_parameters != None and len(rest_parameters) == 2:
        local_path = path_cat(os.path.abspath(path_resolve(rest_parameters[0])), '')
        upstream_path = path_cat(rest_parameters[1], '')
    else:
        print (f'usage: ./pymk.py {sys._getframe().f_code.co_name} [LOCAL PATH] rclone-remote:path')
        return

    bindings = store_get(bindings_prop, default={})
    if binding_check(bindings, local_path, upstream_path):
        # TODO: This will fail on file names containing '
        retval = ex (f'rclone copy --create-empty-src-dirs -P \'{upstream_path}\' \'{local_path}\'')
        if retval == 0:
            bind_locally_existent (bindings, local_path, ':'.join(upstream_path.split(":")[1:]))

def install_dependencies ():
    ex ("sudo apt-get install pip python3-requests-oauthlib python3-googleapi python3-dateutil")
    ex ("sudo pip install google-auth-oauthlib")

if __name__ == "__main__":
    # Everything above this line will be executed for each TAB press.
    # If --get_completions is set, handle_tab_complete() calls exit().
    handle_tab_complete ()

    pymk_default()

