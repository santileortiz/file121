# TODO: This is a mockup of the test cases I've seen necessary. Actually
# implement functions necessary to be able to run them. Then fix the diff
# algorithm so all of them pass. Maybe use decorators to implement the logging
# of test results?

# TEST 1
bindings = {
    '/': '/home/user/Drive/',
    '/datadir': '/home/user/datadir',
    }

local_tree = {}
tree_ensure_path (local_tree, '/home/user/Drive/')
f = tree_ensure_path (local_tree, '/home/user/datadir/datafile')

remote_tree = {}
tree_ensure_path (remote_tree, '/datadir/datafile', node=f)

diff_results = compute_diff(local_tree, remote_tree, bindings)

all_equal = True
for diff_result in diff_results:
    if not diff_result.is_equal:
        all_equal = False
        break

if all_equal:
    print (ecma_green('SUCCESS'))
else:
    print (ecma_green('FAIL'))


# TEST 2
bindings = {
    '/': '/home/user/Drive/',
    '/MyData/datadir1': '/home/user/datadir1',
    '/MyData/datadir2': '/home/user/datadir2',
    }

local_tree = {}
tree_ensure_path (local_tree, '/home/user/Drive/')
f1 = tree_ensure_path (local_tree, '/home/user/datadir1/datafile1')
f2 = tree_ensure_path (local_tree, '/home/user/datadir2/datafile2')

remote_tree = {}
tree_ensure_path (remote_tree, '/MyData/datadir1/datafile1', node=f1)
tree_ensure_path (remote_tree, '/MyData/datadir2/datafile2', node=f2)

diff_results = compute_diff(local_tree, remote_tree, bindings)

all_equal = True
for diff_result in diff_results:
    if not diff_result.is_equal:
        all_equal = False
        break

if all_equal:
    print (ecma_green('SUCCESS'))
else:
    print (ecma_green('FAIL'))


# TEST 3
bindings = {
    '/': '/home/user/Drive/',
    '/MyData/datadir1': '/home/user/datadir1',
    '/MyData/datadir2': '/home/user/datadir2',
    }

local_tree = {}
tree_ensure_path (local_tree, '/home/user/Drive/')
f1 = tree_ensure_path (local_tree, '/home/user/datadir1/datafile1')
f2 = tree_ensure_path (local_tree, '/home/user/datadir2/datafile2')

remote_tree = {}
tree_ensure_path (remote_tree, '/MyData/local_missing')
tree_ensure_path (remote_tree, '/MyData/datadir1/datafile1', node=f1)
tree_ensure_path (remote_tree, '/MyData/datadir2/datafile2', node=f2)

diff_results = compute_diff(local_tree, remote_tree, bindings)

success = True
for diff_result in diff_results:
    if diff_result.remote_path == '/' and set(diff_result.local_missing) != set(['/local_missing']):
        success = False
    elif not diff_result.is_equal:
        success = False
        break

if all_equal:
    print (ecma_green('SUCCESS'))
else:
    print (ecma_green('FAIL'))


# TEST 4
bindings = {
    '/': '/home/user/Drive/',
    '/MyData/datadir1': '/home/user/datadir1',
    '/MyData/datadir2': '/home/user/datadir2',
    }

local_tree = {}
tree_ensure_path (local_tree, '/home/user/Drive/')
tree_ensure_path (local_tree, '/MyData/remote_missing')
f1 = tree_ensure_path (local_tree, '/home/user/datadir1/datafile1')
f2 = tree_ensure_path (local_tree, '/home/user/datadir2/datafile2')

remote_tree = {}
tree_ensure_path (remote_tree, '/MyData/datadir1/datafile1', node=f1)
tree_ensure_path (remote_tree, '/MyData/datadir2/datafile2', node=f2)

diff_results = compute_diff(local_tree, remote_tree, bindings)

success = True
for diff_result in diff_results:
    if diff_result.remote_path == '/' and set(diff_result.remote_missing) != set(['/remote_missing']):
        success = False
    elif not diff_result.is_equal:
        success = False
        break

if success:
    print (ecma_green('SUCCESS'))
else:
    print (ecma_green('FAIL'))
