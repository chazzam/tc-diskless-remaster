#!/usr/local/bin/python
"""
Remaster a TinyCore for diskless operation
"""
import subprocess
#import re
#~ import getpass, os.path, pickle, cStringIO, sys
#~ from termios import tcflush, TCIFLUSH
from os.path import \
    isfile, isdir, dirname, expanduser, realpath, expandvars, abspath
import ConfigParser

# Update to not managing tc-ext-tools at all, support a flag to specify a location
# in which to search for extensions beyond the normal installed directory.
# make sure to support searching it recursively!

# add a second python or bash script to manage automating tc-ext-tools building
# Make it accept the same config file and
# build stuff in: onboot,optional_ext[s],required_ext[s],additional_ext[s]
# /etc/sysconfig/tcedir/
# /etc/sysconfig/tcedir/optional/

# Try using .tree files to build dependency trees? Keep the shortest # preceeding spaces
# Have to exclude the first line though? the first line is the extension itself.

_HOME = expandvars("$HOME")
_HOME = expanduser("~")

def existing_dir(value):
    """verify argument is or references an existing directory.
    
    One of these conditions must be met:
        the entire value must reference an existing directory
        the dirname(value) must reference an existing directory
        or the current directory is referenced (only a filename given)

    Intended supported examples:
        /tmp/butterworth.txt - Pass
        /tmp                 - Pass
        butterworth.txt      - Pass
        /non/existing/path/  - Fail

    Args:
        value: string path reference

    Returns:
        value: unmodified string path reference

    Raises:
        ArgumentTypeError: If the path cannot be determined to consist of
            already existing directories, and optionally a filename that may or
            may not exist
    """
    dir_name = dirname(value)
    is_dir = isdir(value) or isdir(dir_name) or dir_name == ""
    if value == "" or not is_dir:
        argparse.ArgumentTypeError(
            "Must specify an existing directory for input/output")
    return value

def existing_file(value):
    """verify argument is or references an existing file.
    
    One of these conditions must be met:
        the entire value must reference an existing file

    Intended supported examples:
        /tmp/butterworth.txt - Pass
        /tmp                 - Fail
        butterworth.txt      - Pass
        /non/existing/path/  - Fail

    Args:
        value: string path reference

    Returns:
        value: unmodified string path reference

    Raises:
        ArgumentTypeError: If the path cannot be determined to consist of an
            already existing file
    """
    is_file = isfile(value)
    if value == "" or not is_file:
        argparse.ArgumentTypeError(
            "Must specify an existing file for input")
    return value

def get_options(argv=None):
    """parse the commandline options.

    Check for all supported flags and do any available pre-processing
    """
    import argparse # Requires python 2.7 or newer

    default_config = "remaster.cfg"
    opts = argparse.ArgumentParser(
        description='Provide an initrd image to boot with tinycore.')

    #~ opts.add_argument(
        #~ "--output", "-o", type=existing_dir, help="output directory and/or file"
    #~ )
    opts.add_argument(
#        "--config", "-w", type=argparse.FileType('r'), default=default_config,
        "--config", "-w", default=default_config,
        help="Specify config file for remaster operation")

    # TODO(cmoye) change default to False once the code supports it (version 2+)
    #~ opts.add_argument(
        #~ "--copy2fs-all", "-C", action='store_true', default=True,
        #~ help="Create 'copy2fs.flg' to force copy install for all extensions")
    #~ opts.add_argument(
        #~ "--copy2fs", "-c", nargs="*", 
        #~ help="Create 'copy2fs.lst' to force copy install for given extensions")

    # add default=//path/to/tce/optional/
    #~ opts.add_argument(
        #~ "--extensions-local-dir", "-e", type=existing_dir, nargs="*",
        #~ default=['/tce/optional/upgrades/', '/tce/optional/'],
        #~ help="Specify locally mounted locations to find extensions"
    #~ )
    #~ opts.add_argument(
        #~ "--remote-extensions", "-E", nargs="*",
        #~ help="Specify wget-able extension storage locations to search"
    #~ )

    #~ opts.add_argument(
        #~ "--onboot", "-B", default="", nargs="*", help=argparse.SUPPRESS
    #~ )
    #~ opts.add_argument(
        #~ "--available_ext", "-A", default="", nargs="*", help=argparse.SUPPRESS
    #~ )
    opts.add_argument(
        "--install-root", "-O", default="/mnt/digium/",
        help=argparse.SUPPRESS)

    #~ opts.add_argument(
        #~ "--write-config", "-W", action='store_true', default=False,
        #~ help="Write the specified config file using passed in args"
    #~ )
    #~ opts.add_argument(
        #~ "--combined-init", "-I", action='store_true', default=False,
        #~ help="merge the created init with core.gz to create one init image"
    #~ )
    #~ opts.add_argument(
        #~ "--initial-init", "-i", type=argparse.FileType('r'),
        #~ help="Specify the initial 'core.gz' with which to combine init"
    #~ )
    #~ opts.add_argument(
        #~ "--unsquash-exts", "-U", action='store_true', default=False,
        #~ help="should we attempt to unsquash the extensions into the init"
    #~ )
    #~ opts.add_argument(
        #~ "--unsquash-user", "-u", default="tc",
        #~ help="Specify the user to setup when unsquashing extensions"
    #~ )
    #~ # TODO (chazzam) Add '-O <config param> <config value>' as a command-line option
    args = opts.parse_args(argv)
    return args

def read_configuration(args):
    """Read the configuration file and add in commandline parameters

    Read in the config file specified from command-line

    Pull in any relevant command-line parameters that should be stored for later
    """
    from os.path import basename, splitext
    from os.path import join as path_join
    config = ConfigParser.SafeConfigParser(vars(args))
    try:
        config.read(args.config)
    except ConfigParser.Error:
        return None
    # Create the internal sections
    a = "args"
    i = "install"
    for x in [a, i]:
        if not config.has_section(x):
            config.add_section(x)

    # Add the args to the config
    # TODO (chazzam) overwrite install with args instead of saving separately
    # TODO (Chazzam) do the output nonsense in this loop
    for opt in iter(vars(args)):
        if vars(args).get(opt,"") != "":
            config.set(a, opt, str(vars(args).get(opt)))
    # Handle setting the output?
    # Check for an output in config, but replace it with the one in arg if both specify file
    # Check for a basename in args.output
    config_ofolder = ""
    config_ofile = ""
    args_ofolder = ""
    args_ofile = ""
    final_output = ""

    if config.has_option(i, "output"):
        config_ofolder = abspath(dirname(config.get(i, "output")))
        config_ofile = basename(config.get(i, "output"))
        if not isdir(config_ofolder):
            config_ofolder = ""
        if config_ofile == "":
            config_ofile = splitext(basename(args.config))[0]
            config_ofile = "".join([config_ofile,".gz"])
    aout = vars(args).get("output","")
    if aout != "":
        args_ofolder = abspath(dirname(aout))
        args_ofile = basename(aout)
        if not isdir(args_ofolder):
            args_ofolder = ""
    if args_ofile != "":
        final_output = aout
    elif isdir(args_ofolder):
        final_output = path_join(args_ofolder, config_ofile)
    else:
        # This shouldn't happen if argparse is working correctly
        if config_ofolder == "":
            config_ofolder = abspath("./")
        final_output = path_join(config_ofolder, config_ofile)
    final_output = realpath(abspath(final_output))
    # 1. args specifies a full path/file
    # 2. args specifies a directory and config specifies an output file
    # 3. args specifies a directory and config specifies a full path (keep basename)
    # 4. args specifies a directory and we reuse the config filename as the output file base name
    # 5. no args, config specifies a folder or we use cwd, config specifies a filename or we use config filename
    config.set(i, "output", final_output)
    return config
    
def disable_sigpipe():
    import signal
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)

def _call_output(command, throw=False):
    import subprocess
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT, preexec_fn=disable_sigpipe)
    stdout = proc.communicate()[0]
    res = proc.returncode
    if throw and res:
        raise Exception("Failed call to '%s'" % (command))
    return stdout

def static_var(varname, value):
    def decorate(func):
        setattr(func, varname, value)
        return func
    return decorate

@static_var("kernel", "")
def extensionize_names(extensions):
    """Update a set of extensions names

    Make sure each name ends in .tcz
    Replace 'KERNEL' with current kernel version
    
    Args:
        extensions: a set of extension names
    Returns:
        extensions: set of potentially valid tcz extension names
    """
    if extensionize_names.kernel == "":
        #build_dependency_tree.kernel = "3.0.21-tinycore"
        extensionize_names.kernel = _call_output('uname -r').strip()
    for raw_ext in extensions.copy():
        safe_ext = raw_ext.replace("KERNEL", extensionize_names.kernel)
        if not safe_ext.endswith(".tcz"):
            safe_ext += ".tcz"
        if safe_ext == raw_ext:
            continue
        extensions.discard(raw_ext)
        extensions.add(safe_ext)
    return extensions

def recursive_dirs(dirs):
    """Get subdirs for given dirs

    Get all the sub directories of the passed in dirs, be they symlinks or not
    
    Args:
        dirs: list of directory paths, can be symlinks
    Returns:
        set: abspath of initial directories and subdirs with symlinks dereferenced
    """
    from os import listdir
    raw_dirs = set(dirs)
    safe_dirs = set()
    for raw_dir in raw_dirs.copy():
        safe_dir = realpath(abspath(expandvars(raw_dir)))
        if not isdir(safe_dir):
            #raw_dirs.remove(raw_dir)
            continue
        safe_dirs.add(safe_dir)
        safe_dirs.update(recursive_dirs(listdir(safe_dir)))
    return safe_dirs

def demote(user_uid, user_gid):
    def result():
        from os import setgid, setuid
        setgid(user_gid)
        setuid(user_uid)
    return result

def get_dot_deps(dep):
    """read in dependencies from .dep file

    Args:
        extension: the dep file for an extension to read

    Returns:
        set: unique dependent extensions
    """
    #
    #from os.path import isfile
    if not dep.endswith(".dep"):
        dep += ".dep"
    deps = set()
    if not isfile(dep):
        return deps
    with open(dep) as f:
        for line in f:
            new_dep = line.strip()
            if new_dep == "":
                continue
            deps.add(new_dep)
    #~ try:
        #~ 
        #~ deps.update([line.strip() for line in open(dep)])
        #~ close(dep)
    #~ except:
        #~ return deps
        #~ #pass
    deps = extensionize_names(deps)
    return deps

def get_deps(dirs, extensions, path_exts=None):
    """Get absolute dereferenced paths to all needed extensions

    Identify absolute dereferenced path to an extension, and pul in any
    dependencies found in its .dep file as well
    
    Args:
        dirs: list of directories to search for extensions
        extensions: set of extensions(s) to locate
        path_exts: internal dictionary for keeping up with which extensions
            have been found so far

    Returns:
        set: absolute paths to all needed extensions
    """
    from os.path import basename, join
    from os import getuid

    if path_exts == None:
        path_exts = {}
    for raw_ext in extensions.copy():
        if raw_ext in path_exts:
            continue
        # Can't run tce-load as root user, so demote this call if needed
        dl_cmd = ['tce-load', '-w', raw_ext]
        if (getuid == 0):
            # these are the default values for tc:staff in TC
            # not 100% sure we need to modify the gid to work...
            subprocess.call(dl_cmd, preexec_fn=demote(1001,50))
        else:
            subprocess.call(dl_cmd)
        for t_dir in dirs:
            raw_dirs = recursive_dirs([t_dir])
            if len(raw_dirs) == 0:
                continue
            found_dir = False
            for raw_dir in raw_dirs:
                path_ext = join(raw_dir, raw_ext)
                if not isfile(path_ext):
                    continue
                path_exts[raw_ext] = path_ext
                dep = path_ext + ".dep"
                if isfile(dep):
                    extensions.update(get_dot_deps(dep))
                found_dir = True
                break
            if found_dir:
                break
        else:
            # Need to fail here, because we never found the extension
            print "Could not find extension: ", raw_ext
            exit(1)
    # If we're done: return complete deps list;
    # or send it deeper
    if (len(path_exts) != len(extensions)):
        return get_deps(dirs, extensions, path_exts)
    extensions.clear()
    for ext in path_exts.itervalues():
        extensions.add(ext)
    return extensions

def mkdir_p(path):
    # https://stackoverflow.com/questions/600268/mkdir-p-functionality-in-python
    import os, errno
    try:
        os.makedirs(path)
    except OSError as exc: # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else: raise

def write_onboot_lst(onboots, path):
    if len(onboots) == 0:
        return

    from os.path import join

    print "Writing onboot.lst"
    onboot_lst = join(path, 'onboot.lst')
    with open(onboot_lst, 'w') as f:
        for ext in onboots:
            f.write('{0}\n'.format(ext))

def write_copy2fs(copy2fs_exts, path):
    if len(copy2fs_exts) == 0:
        return

    from os.path import join

    copy2fs = join(path, 'copy2fs.lst')
    if ("all" in copy2fs_exts) or ("flag" in copy2fs_exts):
        copy2fs.replace(".lst", ".flg")
        print "Creating copy2fs.flg"
        subprocess.call(['touch', copy2fs])
        return

    print "Writing copy2fs.lst"
    extensions = copy2fs_exts.split(',')
    with open(copy2fs, 'w') as f:
        for ext in extensions:
            f.write('{0}\n'.format(ext))

def tc_bundle_path(dir_path, bundle):
    # chdir dir_path
    #sudo find | sudo cpio -v -o -H newc | gzip -2 -v > bundle
    # advdef -z4 bundle
    from os.path import join
    #chdir(dir_path)
    gzip_lvl = 9
    subprocess.call(['mv', '-f', bundle, bundle + '.old'])
    if (subprocess.call('advdef >/dev/null 2>&1',shell=True) == 0):
        gzip_lvl = 2
    print "Packaging the additional init image, this can take a few moments..."
    subprocess.call(
        'find|cpio -o -H newc|gzip -{1} > {0}'.format(bundle, gzip_lvl),
        cwd=dir_path, shell=True)
    if gzip_lvl == 2:
        print "Further compressing the bundle with 'advdef', please wait..."
        subprocess.call(['advdef', '-z4', bundle])
    print "processed config into initrd file: {0}".format(bundle)

def copy_extensions(dir_path, extensions):
    # Copy .tcz, .tcz.dep, .tcz.md5.txt, .tcz.list, and .tcz.info
    for ext in extensions:
        subprocess.call(
            "cp -fp {0} {0}.dep {0}.md5.txt {0}.list {0}.info {1} 2>/dev/null".\
            format(ext, dir_path),
            shell=True)

def main(argv=None):
    """Main function of script.

    processes command line args, config file, and carries out operations
    needed to build initrd image for booting with the needed file structure
    """
    from sys import argv as sys_argv
    from shutil import rmtree
    from tempfile import mkdtemp
    from os.path import join

    if argv is None:
        argv = sys_argv
    args = get_options(argv[1:])
    # Build the config object to pass around
    config = None
    try:
        config = read_configuration(args)
    except:
        pass
    if config is None:
        print "ERROR: Could not process configuration file"
        return 1
    # Build current list of extensions (extensions + onboot)
    extension_list = set()
    onboot_list = set()
    copy2fs_list = set()
    if config.has_option("install", "extensions"):
        extension_list.update((config.get("install", "extensions")).split(','))
        extension_list = extensionize_names(extension_list)
    if config.has_option("install", "onboot"):
        onboot_list.update((config.get("install", "onboot")).split(','))
        onboot_list = extensionize_names(onboot_list)
        extension_list.update(onboot_list)
    if config.has_option("install", "copy2fs"):
        copy2fs_list.update((config.get("install", "copy2fs")).split(','))
        copy2fs_list = extensionize_names(copy2fs_list)
        extension_list.update(copy2fs_list)
        # make sure there are no duplicates in onboot, and that it has .tcz
    config.set("install", "onboot", ','.join(onboot_list))
    config.set("install", "copy2fs", ','.join(copy2fs_list))
    config.set("install", "extensions", ','.join(extension_list))

    # Setup directory list default for extension searching
    dir_list = []
    if config.has_option("install", "extensions_local_dir"):
        dir_list = config.get("install", "extensions_local_dir").split(',')
    dir_list.append('/etc/sysconfig/tcedir/optional/')
    config.set("install", "extensions_local_dir", ','.join(dir_list))

    # Need to verify all of them end in .tcz
    # Need to build an absolute path to all of the extensions
    # Recursively determine all dependencies
        # Assume any extension in a local dir will have its .dep if it exists.
        # If any extension is never found, try to tce-load -w it
        # If still can't get an absolute path to everything, fail.
    # Get a flattened list of needed extensions
    extension_list = get_deps(dir_list, extension_list)

    print config.get("install", "output")
    work_root = mkdtemp(prefix="remaster")
    work_dir = join(work_root, config.get("install", "install_root").lstrip('/'))
    work_install = join(work_dir, "optional/")
    mkdir_p(work_install)
    # Create temp working directory for install, mkdir -p install_root 'tce'
    # setup folder structure within temp dir
    # copy everything to temp dir
    copy_extensions(work_install, extension_list)
    # write copy2fs.* and onboot.lst if needed
    write_onboot_lst(onboot_list, work_dir)
    if config.has_option("install", "copy2fs"):
        write_copy2fs(config.get("install", "copy2fs"), work_dir)
    # squashfs the needful
    # gzip and advdef if it possible
    tc_bundle_path(work_root, config.get("install", "output"))
    rmtree(work_root)
    return 0

"""allow unit testing and single exit point.

checking the __name__ before running allows inporting as a module, to the
python interactive interpreter and allows unit testing

calling sys.exit here may allow for single point of exit within the script
"""
if __name__ == '__main__':
    from sys import exit, hexversion
    if hexversion < 0x02070000:
        print "ERROR: Requires Python 2.7.0 or newer"
        exit(1)
    exit(main())
