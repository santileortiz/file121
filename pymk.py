#!/usr/bin/python3
from mkpy.utility import *
import google_utility as google
from datetime import datetime, timezone
import dateutil.parser
import hashlib
import traceback
import stat

import mimetypes
from googleapiclient.http import MediaFileUpload

import pdb

# TODO: Unify file_dict and file_tree into a single file. Create a common type
# of datastructure for local and upstream tree files.
file_dict_fname = 'file_dict'
file_tree_fname = 'file_tree'
local_file_tree_fname = 'local_file_tree'
abs_local_file_tree_fname = os.path.abspath(path_resolve(local_file_tree_fname))

to_upload_fname = 'to_upload'
to_remove_fname = 'to_remove'
to_update_fname = 'to_update'

changes_token_prop = 'changes_token'
bindings_prop = 'bindings'

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
        if 'parents' in node.keys():
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
        files = pickle_load (file_dict_fname)

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

    pickle_dump (files, file_dict_fname)
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

def recursive_tree_print(node, indent=''):
    print (indent + node['name'])
    if 'c' in node.keys():
        for child in node['c']:
            recursive_tree_print(child, indent=indent + ' ')

def recursive_path_tree_print(node, path=''):
    print (path_cat(path, node['name']))
    if 'c' in node.keys():
        for name, child in node['c'].items():
            recursive_path_tree_print(child, path=path_cat(path, node['name']))

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
    file_dict = pickle_load (file_dict_fname)

    root = {}
    for f_id, f in file_dict.items():
        # Ensure all directories have a children dictionary, even if it's
        # empty. Currently when computing the diff we distinguish between files
        # and directories by the presence/abscence of this value.
        if 'mimeType' in f.keys() and f['mimeType'] == "application/vnd.google-apps.folder" and 'c' not in f.keys():
            f['c'] = {}

        if 'mimeType' not in f.keys():
            print (f'ERROR!!!!: {f_id}, {f}')

        if 'parents' in f.keys():
            for parent_id in f['parents']:
                if parent_id in file_dict.keys():
                    tree_set_child (file_dict[parent_id], f)
        else:
            root[f['name']] = f

    pickle_dump (root, file_tree_fname)

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
                if sequential_file_dump[id]['md5Checksum'] != sequential_file_dump[oldest_id]['md5Checksum']:
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
    # NOTE: It's possible that we get duplicates while building the file name
    # tree but not here. That's because the full file dump contains shared
    # folders to, and here we assume the passed path has the user's 'My Drive'
    # as root.

    path = '/'
    if len(sys.argv) > 2:
        path = sys.argv[2]
    path_lst = path_as_list(path)

    file_name_tree = pickle_load (file_tree_fname)
    node = lookup_path (file_name_tree['My Drive'], path_lst)

    if get_cli_bool_opt('--remove'):
        file_dict = pickle_load (file_dict_fname)
        to_remove = {}
        recursive_name_duplicates_print_collect_removal(path, node, to_remove, file_dict)
        print (to_remove)

    else:
        recursive_name_duplicates_print(path, node)

def remove_name_duplicates():
    """
    Receives an upstream path of a subtree and removes all distinct upstream
    files with duplicate names. It keeps the oldest version of a file.

    Pass --dry-run to get a list of what would be deleted without actually doing so.
    """
    # NOTE: It's possible that we get duplicates while building the file name
    # tree but not here. That's because the full file dump contains shared
    # folders to, and here we assume the passed path has the user's 'My Drive'
    # as root.

    path = '/'
    if len(sys.argv) >= 2:
        path = sys.argv[2]
    path_lst = path_as_list(path)

    file_name_tree = pickle_load (file_tree_fname)
    node = lookup_path (file_name_tree['My Drive'], path_lst)

    file_dict = pickle_load (file_dict_fname)
    to_remove = {}
    recursive_name_duplicates_print_collect_removal(path, node, to_remove, file_dict)

    is_first = True
    service = google.get_service()
    for kept, removed_ids in to_remove.items():
        if not is_first:
            print()
        else:
            is_first = False

        equality = ecma_yellow('DIFFERENT')
        if kept[2]:
            equality = ecma_green('EQUAL')

        print (f"{equality}")
        info (f"U '{kept[0]}'")
        print (f"Keeping '{kept[1]}'")
        for file_id in removed_ids:
            if not get_cli_bool_opt('--dry-run'):
                remove_file_id (service, file_id)
            print (f"R {file_id}")

    # TODO: Update upstream tree

def set_file_entry(node_children, abs_path, fname=None, f_stat=None, status=None):
    if f_stat == None:
        f_stat = os.stat(abs_path)

    if fname == None:
        fname = path_basename(abs_path)

    success = False
    if stat.S_ISREG(f_stat.st_mode):
        if abs_path != abs_local_file_tree_fname:
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

    for dirname in path_lst:
        if dirname not in node['c'].keys():
            node['c'][dirname] = {'name':dirname, 'c':{}}
        node = node['c'][dirname]
    return node

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
        node = ensure_tree_dirpath (path_lst, local_file_name_tree)

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
    stat = Status()

    if len(sys.argv) > 2:
        path = sys.argv[2]
        path = os.path.abspath(path_resolve(path))

        local_file_name_tree = get_local_file_tree(path, status=stat)
        pickle_dump (local_file_name_tree, local_file_tree_fname)

    else:
        local_file_name_tree = {}
        for upstream_path, local_path in store_get(bindings_prop).items():
            info (f'L {local_path}')
            get_local_file_tree (local_path, local_file_name_tree=local_file_name_tree, status=stat)

        pickle_dump (local_file_name_tree, local_file_tree_fname)

    print()
    print (stat)

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
            print (f'R {path_cat(abs_path, removed)}')

        for removed in removed_files:
            del old_nodes[removed]
            print (f'R {path_cat(abs_path, removed)}')

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

    file_dict = pickle_load(file_dict_fname)
    if f_id in file_dict.keys():
        f = file_dict[f_id]
        if is_root_node(f):
            print ('(root)')
        for attr in f.keys():
            print (f'{attr}: {f[attr]}')
    else:
        print ('File id not found: {f_id}')


def update_upstream_file_name_tree():
    # TODO: Test these cases:
    #  - What happens when thrashing/removing a subtree?, I would guess we get
    #    a change object for each folder/file in it.
    #  - What happens when files/subtrees are moved?.


    #  Information of permanently removed files can't be accessed anymore, so
    #  the 'file' attribute of the change object won't be present. The id of
    #  the removed file will come in the 'fileId' attribute of the change
    #  object. This will happen for example when the thrash bin is emptied.
    #
    #  This is why we don't filter out thrashed files here, like we do in
    #  sequential_file_dump().
    parameters = {'fields':'newStartPageToken,changes(fileId,changeType,removed,file(id,name,mimeType,modifiedTime,md5Checksum,parents,trashed))', 'pageSize':1000}
    parameters['pageToken'] = store_get(changes_token_prop)

    changed = False
    file_dict = pickle_load(file_dict_fname)
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
                        else:
                            path = change

                        if f_id in file_dict.keys():
                            del file_dict[f_id]
                            print(f'R {path}')
                        else:
                            print(f'R? {path}')

                    elif 'file' in change.keys():
                        f = change['file']
                        set_upstream_file_entry (file_dict, f)
                        path = get_file_path(file_dict, file_dict[f_id])

                        if path != None:
                            if f_id in file_dict_old.keys():
                                if 'md5Checksum' not in f.keys():
                                    print(f'U {path}')
                                else:
                                    old_hash = file_dict_old[f_id]['md5Checksum']
                                    print(f'U {old_hash} -> {f["md5Checksum"]} - {path}')

                            else:
                                if 'md5Checksum' not in f.keys():
                                    print(f'N {path}')
                                else:
                                    print(f'N {f["md5Checksum"]} - {path}')

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
        pickle_dump (file_dict, file_dict_fname)
        build_file_name_tree()

def update_local_file_name_tree():
    status = Status()

    local_file_name_tree = pickle_load (local_file_tree_fname)
    for upstream_path, local_path in store_get(bindings_prop).items():
        info (f'L {local_path}')
        local_path_lst = path_as_list (local_path)

        binding_root = lookup_path(local_file_name_tree, local_path_lst, silent=True)
        assert binding_root != None
        # :file_bindings would need a separate case.
        recursive_update_local_file_tree (local_path_lst, binding_root, local_file_name_tree, status=status)

    print (status)
    pickle_dump (local_file_name_tree, local_file_tree_fname)

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
        print ('Missing arguments.')
        return

    bindings = store_get(bindings_prop, default={})
    local_path = bindings[upstream_path]
    local_file_name_tree = pickle_load (local_file_tree_fname)

    path_lst = path_as_list(local_path)
    node = lookup_path (local_file_name_tree, path_lst)
    parent = lookup_path (local_file_name_tree, path_lst[:-1])
    children = parent['c']

    del children[node['name']]
    pickle_dump (local_file_name_tree, local_file_tree_fname)

    del bindings[upstream_path]
    store(bindings_prop, bindings)

def binding_add():
    if len(sys.argv) > 2:
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
        local_path = path_cat(os.path.abspath(path_resolve(sys.argv[2])), '')
        upstream_path = path_cat(sys.argv[3], '')
    else:
        print ('Missing arguments.')
        return

    # Make sure the binding is new
    # TODO: Implement binding update
    bindings = store_get(bindings_prop, default={})
    if upstream_path in bindings.keys():
        if local_path == bindings[upstream_path]:
            print (f"Binding already exists: '{local_path}' -> '{upstream_path}'")
        else:
            print (f"Upstream directory already bound: '{upstream_path}'")
        return
    elif local_path in {local_p for _, local_p in bindings.items()}:
        print (f"Local directory already bound: '{local_path}'")
        return

    # The whole code keeps the invariant that binding folders always exist in
    # both local and upstream trees. Here we make sure that's the case so we
    # don't get failures later.
    #
    # NOTE: This means we need to explicitly handle the case of someone
    # restoring their configuration manually. Either we need an explicit
    # "reload_config" command, or everytime a tree cache is loaded we must make
    # sure bound paths exist in the tree.
    upstream_tree = pickle_load (file_tree_fname)['My Drive']

    # Currently bindings can only be added to upload a directory
    # TODO: Implement binding addition to download directories
    upstream_tree_node = lookup_path (upstream_tree, path_as_list(upstream_path), silent=True)
    if path_exists(local_path) and path_isdir(local_path) and upstream_tree_node == None:
        local_file_name_tree = pickle_load (local_file_tree_fname)

        path_lst = path_as_list(local_path)
        local_tree_node = lookup_path (local_file_name_tree, path_lst, silent=True)
        if local_tree_node == None:
            ensure_tree_dirpath (path_lst, local_file_name_tree)
            pickle_dump (local_file_name_tree, local_file_tree_fname)

            service = google.get_service()
            ensure_upstream_dir_path (service, local_path, upstream_tree, upstream_path)
            # Should we upload the directory here? Right now we don't, user
            # needs to call diff, then push.

            bindings[upstream_path] = local_path
            store(bindings_prop, bindings)

            update_local_file_name_tree()
            update_upstream_file_name_tree()

        else:
            print ("Invalid binding: local directory is already part of local file tree.")

    elif not path_exists(local_path) and upstream_tree_node != None and is_dir_node(upstream_tree_node):
        print ("Bindings that download subtrees aren't implemented.")

    elif path_exists(local_path) and path_isdir(local_path) and upstream_tree_node != None and is_dir_node(upstream_tree_node):
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

def print_diff_output(checksum_count, children_count, upstream_subtree, local_subtree, bound_roots=None):
    # TODO: Use a --verbose flag to force full output evenif subtrees are equal.

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
        print(ecma_green("EQUAL"))
    else:
        print ()
        print (f'Successful checksum comparisons: {checksum_count}')
        print (f'Children name comparisons: {children_count}')
        print (f'Upstream subtree size: {upstream_file_count}/{upstream_children_count}')
        print (f'Local subtree size: {local_file_count}/{local_children_count}')

def diff():
    if len(sys.argv) == 4:
        local_path = os.path.abspath(path_resolve(sys.argv[2]))
        upstream_path = sys.argv[3]

        if get_cli_bool_opt('--build-local'):
            local_tree = get_local_file_tree(local_path)
            print()
        else:
            local_tree = pickle_load(local_file_tree_fname)
        local_path_lst = path_as_list(local_path)
        local_subtree = lookup_path (local_tree, local_path_lst)

        upstream_tree = pickle_load(file_tree_fname)
        upstream_path_lst = path_as_list(upstream_path)
        upstream_subtree = lookup_path (upstream_tree['My Drive'], upstream_path_lst)

        missing_upstream, missing_locally, different, checksum_count, children_count = \
            recursive_tree_compare(local_subtree, upstream_subtree)

        for fpath in different:
            print (f'Different: {fpath}')

        for fpath in missing_upstream:
            print (f'Missing upstream: {fpath}')

        for fpath in missing_locally:
            print (f'Missing locally: {fpath}')

        print_diff_output(checksum_count, children_count, upstream_subtree, local_subtree)

    elif len(sys.argv) == 2:
        local_tree = pickle_load(local_file_tree_fname)
        upstream_tree = pickle_load(file_tree_fname)

        to_upload = {}
        to_update = {}
        to_remove = set()
        is_first = True
        bindings = store_get(bindings_prop)
        for upstream_path, local_path in bindings.items():
            local_path_lst = path_as_list(local_path)
            local_subtree = lookup_path (local_tree, local_path_lst)

            upstream_path_lst = path_as_list(upstream_path)
            upstream_subtree = lookup_path (upstream_tree['My Drive'], upstream_path_lst)

            missing_upstream, tmp_missing_locally, different, checksum_count, children_count = \
                recursive_tree_compare(local_subtree, upstream_subtree)

            if not is_first:
                print()
            is_first = False

            info (f"U '{upstream_path}'")
            info (f"L '{local_path}'")

            for fpath in different:
                to_update[f'{path_cat(local_path, fpath)}'] = f'{path_cat(upstream_path, fpath)}'
                print (f'Different: {fpath}')

            for fpath in missing_upstream:
                to_upload[f'{path_cat(local_path, fpath)}'] = f'{path_cat(upstream_path, fpath)}'
                print (f'Missing upstream: {fpath}')

            # Bound directories will be counted as missing locally on the root
            # comparison, here we remove those from the actual list of files missing
            # upstream.
            missing_locally = []
            contained_bound = set()
            for fpath in tmp_missing_locally:
                # TODO: When we support binding files upstream, we shouldn't force
                # the upstream path to be terminated by '/'.

                # FIXME: Let's say we have binding A that has a bound subtree
                # B, if B's immediate parent is missing from A's subtree, it
                # will be marked for removal because the path to the parent
                # isn't exactly a key of the bindings map.
                #
                # Also, if we have a full path missing, like /A/B/C, the tree
                # comparison should report the minimal set of nodes that
                # represent it. If all A, B and C are empty (besides it's
                # immediate file), only A should be present as missing, not all
                # 3 directories. How we handle this will affect the fix for the
                # problem above.
                upstream_fpath = path_cat(upstream_path, fpath, '')
                if upstream_fpath not in bindings.keys():
                    to_remove.add(f'{path_cat(upstream_path, fpath)}')
                    print (f'Missing locally: {fpath}')
                    missing_locally.append (fpath)
                else:
                    print (f'Bound Subtree: {fpath}')
                    contained_bound.add (canonical_path(path_cat(upstream_path,fpath)))

            print_diff_output(checksum_count, children_count, upstream_subtree, local_subtree,
                    bound_roots=contained_bound)


        if len(to_upload) + len(to_remove) + len(to_update) > 0:
            print()

        py_literal_dump (to_upload, to_upload_fname)
        if len(to_upload) > 0:
            print (f'Added files to be uploaded to: {to_upload_fname}')

        py_literal_dump (list(to_remove), to_remove_fname)
        if len(to_remove) > 0:
            print (f'Added files to be removed to: {to_remove_fname}')

        py_literal_dump (to_update, to_update_fname)
        if len(to_update) > 0:
            print (f'Added files to be updated to: {to_update_fname}')

    else:
        print ('Invalid arguments.')

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
        print (f"R {upstream_abs_path}")
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

        print (f"N {local_abs_path} -> {upstream_abs_path}")

        request = service.files().create(body=file_metadata, media_body=data)
        google.request_execute_cli(request)

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

        print (f"C {local_abs_path} -> {upstream_abs_path}")

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
        print (f"N {path_cat(upstream_abs_path, '')}")

def upload_path (local_abs_path, upstream_abs_path, service=None, upstream_root=None, status=None):
    """
    Uploads ether a file or a directory recursively
    """

    if service == None:
        service = google.get_service()

    if upstream_root == None:
        upstream_tree = pickle_load(file_tree_fname)
        upstream_root = upstream_tree['My Drive']


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
    to_upload = py_literal_load (to_upload_fname)

    if len(to_upload) > 0:
        upstream_tree = pickle_load(file_tree_fname)
        upstream_root = upstream_tree['My Drive']

        stat = Status()
        service = google.get_service()
        for local_abs_path, upstream_abs_path in to_upload.items():
            upload_path (local_abs_path, upstream_abs_path, service=service, upstream_root=upstream_root, status=stat)

        # Because the output can be very long, summarize all messages at
        # the end
        print (stat)

    else:
        print ('List of files to upload is empty.')

def push():
    # TODO: Make all of this process less verbose and have a consistent CLI
    # output.

    update_upstream_file_name_tree()
    update_local_file_name_tree()
    diff()

    stat = Status()
    to_upload = py_literal_load (to_upload_fname)
    to_update = py_literal_load (to_update_fname)
    to_remove = py_literal_load (to_remove_fname)

    if len(to_upload) > 0 or len(to_update) > 0:
        upstream_tree = pickle_load(file_tree_fname)
        upstream_root = upstream_tree['My Drive']

        service = google.get_service()

    if len(to_upload) > 0:
        for local_abs_path, upstream_abs_path in to_upload.items():
            upload_path (local_abs_path, upstream_abs_path, service=service, upstream_root=upstream_root, status=stat)

    if len(to_update) > 0:
        for local_abs_path, upstream_abs_path in to_update.items():
            update_file (service, local_abs_path, upstream_root, upstream_abs_path, status=stat)

    if len(to_remove) > 0:
        for upstream_abs_path in to_remove:
            remove_file (service, upstream_root, upstream_abs_path, status=stat)

    update_upstream_file_name_tree()

    # Because the output can be very long, summarize all messages at
    # the end
    print (stat)
    

if __name__ == "__main__":
    # Everything above this line will be executed for each TAB press.
    # If --get_completions is set, handle_tab_complete() calls exit().
    handle_tab_complete ()

    pymk_default()

