#!/usr/bin/python3
from mkpy.utility import *
import google_utility as google
from datetime import datetime, timezone
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
to_upload_fname = 'to_upload'

bindings_prop = 'bindings'

def default ():
    target = store_get ('last_snip', default='example_procedure')
    call_user_function(target)

def sequential_file_dump ():
    """
    This requests all file information from google drive and dumps it into a
    file representing a dictionary indexed by id. It gets enough information
    for us to compare the upstream file with one downstream.
    """

    restart = get_cli_bool_opt('--restart')
    progress_flag_name = 'sequentialTraversalInProgress'
    is_in_progress = store_get(progress_flag_name, default=False) and not restart

    parameters = {'fields':'nextPageToken,files(id,mimeType,name,md5Checksum,parents)', 'pageSize':1000, 'q':'trashed = false'}

    success = False
    files = {}
    if is_in_progress:
        print ('Detected partially complete dump, restarting using stored page token.')
        parameters['pageToken'] = store_get('nextPageToken')
        files = pickle_load (file_dict_fname)

    while True:
        try:
            r = google.get('https://www.googleapis.com/drive/v3/files', params=parameters)
        except Exception as e:
            print ('Error while performing request to Google, dump can be restarted by re running the command.')
            print (traceback.format_exc())
            store(progress_flag_name, True)
            break

        if 'files' in r.keys():
            for f in r['files']:
                f_id = f['id']
                if f_id in files:
                    # This should never happen
                    print (f'Found repeated ID {f_id}')
                files[f_id] = f

            print (f'Received: {len(r["files"])} ({r["files"][-1]["id"] if len(files) > 0 else ""})')
        else:
            print (f'Received response without files.')
            print (r)

        if 'nextPageToken' not in r.keys():
            # Successfully reached the end of the full file list
            store(progress_flag_name, False)
            success = True
            break
        else:
            nextPage_token = r['nextPageToken']
            store('nextPageToken', nextPage_token)
            parameters['pageToken'] = nextPage_token


    if success:
        # For some reason, the sequential file dump still misses some parents. Here
        # we iterate the dump and check that all parent IDs are resolved.  I even
        # tried setting to true 'includeItemsFromAllDrives' and
        # 'supportsAllDrives', it didn't work.
        ghost_file_ids = set()
        for f_id, f in files.items():
            if 'parents' in f.keys():
                for parent_id in f['parents']:
                    if parent_id not in files.keys():
                        ghost_file_ids.add(parent_id)

        # Get data of all ghost files and their ancestors
        #
        # TODO: Maybe these files should be specially marked, like "ghost" files?.
        while len(ghost_file_ids) > 0:
            f_id = ghost_file_ids.pop()
            try:
                f = google.get(f'https://www.googleapis.com/drive/v3/files/{f_id}')
            except:
                print ('Failed to get parent file {f_id}')
                # TODO: Maybe if this happens, the correct solution is
                # to remove the parent reference from the file, so the
                # tree can be built "normally"?. It's possible we will
                # end up adding stuff to the root that's not supposed
                # to be there...

            files[f_id] = f
            if 'parents' in f.keys():
                for parent_id in f['parents']:
                    if parent_id not in files.keys() and parent_id not in ghost_file_ids:
                        ghost_file_ids.add(parent_id)
            print (f'Added ghost file {f_id}')

    pickle_dump (files, file_dict_fname)
    print (f'Total: {len(files)}')

def sequential_file_dump_update():
    # TODO: Implement an update request to the file dump. Use the Changes API
    # from google drive [1]. Save the next page token in the persistent store,
    # then after each update get all changed files and update them in the file
    # dictionary. Careful about this:
    #
    #  - Thrashed files are not really removed, they only get their 'thrashed'
    #    attribute set to true.
    #
    #  - Information of permanently removed files can't be accessed anymore, so
    #    the 'file' attrigute of the change object won't be present. The id of
    #    the removed file will come in the 'fileId' attribute of the change
    #    object. This will happen for example when the thrash bin is emptied.
    #
    #  - The ids parameter in the request should look similar to this
    #       newStartPageToken,changes(fileId,changeType,removed,file(id,trashed,name,md5Checksum,parents))
    # 
    # Some things I haven't tried yet:
    #
    #  - What happens when thrashing/removing a subtree?, I would guess we get
    #    a change object for each folder/file in it.
    #  - What happens when files/subtrees are moved?.
    #
    # [1]: https://developers.google.com/drive/api/v3/reference/changes
    pass

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
        if f['mimeType'] == "application/vnd.google-apps.folder" and 'c' not in f.keys():
            f['c'] = {}

        if 'parents' in f.keys():
            for parent_id in f['parents']:
                if parent_id in file_dict.keys():
                    tree_set_child (file_dict[parent_id], f)
        else:
            root[f['name']] = f

    pickle_dump (root, file_tree_fname)

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

    file_name_tree = pickle_load (file_tree_fname)
    node = lookup_path (file_name_tree['My Drive'], path_lst)
    recursive_name_duplicates_print(path, node)

def set_file_entry(node_children, abs_path, fname=None, f_stat=None):
    if f_stat == None:
        f_stat = os.stat(abs_path)

    if fname == None:
        fname = path_basename(abs_path)

    if stat.S_ISREG(f_stat.st_mode):
        hash_md5 = hashlib.md5()
        with open(abs_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)

        checksum = hash_md5.hexdigest()
        node_children[fname] = {'name':fname, 'md5Checksum':checksum, '_internal_modifiedTime':f_stat.st_mtime}

        print (f'A {checksum} - {abs_path}')

    else:
        log_warning (status, f'Skipping unknown file type (link?): {abs_path}', echo=True)

def get_local_file_tree(path, local_file_name_tree = {}, status=None):
    # TODO: Simplify this. Change local_file_name_tree for a node which we
    # assume is the one pointed to by path. It also should make things faster
    # because we won't be ensuring the whole path exists in each recursive
    # call. It shouldn't be necessary to receive the local_file_name_tree
    # parameter.

    path_lst = []
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
            abs_path = path_cat(dirpath, fname)

            if os.path.isfile(abs_path):
                modified_timestamp = datetime.fromtimestamp(os.path.getmtime(abs_path), timezone.utc)

                hash_md5 = hashlib.md5()
                with open(abs_path, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hash_md5.update(chunk)

                checksum = hash_md5.hexdigest()
                node['c'][fname] = {'name':fname, 'md5Checksum':checksum, '_internal_modifiedTime':modified_timestamp}
                print (f'A {checksum} - {path_cat(dirpath, fname)}')

            else:
                log_warning (status, f'Skipping unknown file type (link?): {abs_path}', echo=True)

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
                set_file_entry(old_nodes, fpath, fname=fname, f_stat=f_stat)
                print (f'U {old_md5} -> {old_nodes[fname]["md5Checksum"]} - {fpath}')

        for fname in added_dirs:
            get_local_file_tree (path_cat(abs_path, fname), local_file_name_tree, status=status)

        for fname in added_files:
            fpath = path_cat(abs_path, fname)
            set_file_entry(old_nodes, fpath, f_stat=f_stat)
            print (f'A {old_nodes[fname]["md5Checksum"]} - {fpath}')

def update_local_file_name_tree():
    local_file_name_tree = pickle_load (local_file_tree_fname)
    for upstream_path, local_path in store_get(bindings_prop).items():
        info (f'L {local_path}')
        local_path_lst = path_as_list (local_path)
        recursive_update_local_file_tree (local_path_lst, lookup_path(local_file_name_tree, local_path_lst), local_file_name_tree)

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
        local_path = path_cat(os.path.abspath(path_resolve(sys.argv[2])), '')
        upstream_path = path_cat(sys.argv[3], '')
    else:
        print ('Missing arguments.')
        return

    bindings = store_get(bindings_prop, default={})
    bindings[upstream_path] = local_path
    store(bindings_prop, bindings)

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

        if len(missing_locally) + len(missing_upstream) + len(different) > 0:
            print ()

        print (f'Successful checksum comparisons: {checksum_count}')
        print (f'Children name comparisons: {children_count}')
        children_count, file_count, *_ = recursive_tree_size(upstream_subtree)
        print (f'Upstream subtree size: {file_count}/{children_count}')
        children_count, file_count, *_ = recursive_tree_size(local_subtree)
        print (f'Local subtree size: {file_count}/{children_count}')

    elif len(sys.argv) == 2:
        local_tree = pickle_load(local_file_tree_fname)
        upstream_tree = pickle_load(file_tree_fname)

        to_upload = {}
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
                upstream_fpath = path_cat(upstream_path, fpath, '')
                if upstream_fpath not in bindings.keys():
                    print (f'Missing locally: {fpath}')
                    missing_locally.append (fpath)
                else:
                    print (f'Bound Subtree: {fpath}')
                    contained_bound.add (canonical_path(path_cat(upstream_path,fpath)))

            if len(tmp_missing_locally) + len(missing_upstream) + len(different) > 0:
                print ()

            # TODO: Collapse output of equal subtrees but print full output for
            # those different. Use a --verbose flag to force full output even
            # if subtrees are equal.
            print (f'{checksum_count}/{children_count} - successful comparisons (checksums/names)')
            children_count, file_count, *_ = recursive_tree_size(upstream_subtree, skip=contained_bound)
            print (f'{file_count}/{children_count} - upstream (files/nodes)')
            children_count, file_count, *_ = recursive_tree_size(local_subtree, skip=contained_bound)
            print (f'{file_count}/{children_count} - local (files/nodes)')

        if len(to_upload) > 0:
            py_literal_dump (to_upload, to_upload_fname)
            print (f'\nAdded files to be uploaded to: {to_upload_fname}')

    else:
        print ('Invalid arguments.')

def upload_file(service, local_abs_path, upstream_root, upstream_abs_path, status=None):
    if not os.path.isfile(local_abs_path):
        log_error (status, f"Can't upload because it's not a file: {local_abs_path}")
        return

    # Find parent in upstream tree
    has_error = False
    path_lst = path_as_list(upstream_abs_path)
    directory_path = path_lst[:-1]
    node = upstream_root

    for dirname in directory_path:
        if 'c' in node.keys() and dirname in node['c'].keys():
            node = node['c'][dirname]
        else:
            log_error (status, f"Can't upload file because directory '{dirname}' doesn't exist upstream: {upstream_abs_path}\n")
            has_error = True
            break

    if not has_error:
        file_metadata = {'name': path_lst[-1], 'parents': [node['id']]}
        data = MediaFileUpload(local_abs_path,
                mimetype=mimetypes.MimeTypes().guess_type(path_lst[-1])[0],
                resumable=True,
                chunksize=1048576)

        print (f"{local_abs_path} -> {upstream_abs_path}")

        print (f'[0%]', file=sys.stderr, end='')
        request = service.files().create(body=file_metadata, media_body=data)
        response = None
        while response is None:
            try:
                status, response = request.next_chunk()
                if status:
                    print (f'\r[{status.progress() * 100:.2f}%]', file=sys.stderr, end='')

            except OSError:
                response = None
                print (f'\r', file=sys.stderr, end='')
                print (f'Error uploading chunk. Retrying...')
                print (f'[0%]', file=sys.stderr, end='')

        print (f'\r', file=sys.stderr, end='')

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
        print (f"In '{os.sep.join(path_lst[:missing_idx])}' created folder(s): {os.sep.join(path_lst[missing_idx:])}")

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

if __name__ == "__main__":
    # Everything above this line will be executed for each TAB press.
    # If --get_completions is set, handle_tab_complete() calls exit().
    handle_tab_complete ()

    pymk_default()

