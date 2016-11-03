#!/usr/bin/env python3.5
"""
Remaster a TinyCore for diskless operation
"""
import subprocess
#import re
#~ import getpass, os.path, pickle, cStringIO, sys
#~ from termios import tcflush, TCIFLUSH
from os.path import \
    isfile, isdir, dirname, expanduser, realpath, expandvars, abspath
import configparser

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

#~ _HOME = expandvars("$HOME")
#~ _HOME = expanduser("~")

class Extension:
    """Tiny Core Extension"""
    def __init__(self, fullname):
        from os.path import dirname, basename
        # Get the filename before dereferencing symlinks
        self.name = basename(Extension.extensionize(fullname))
        self.path = ""
        self.exists = False
        self.update_path(dirname(fullname))
        self.depof = None

    @staticmethod
    def extensionize(name):
        if name == "":
            return name
        if not name.endswith(".tcz"):
            name += ".tcz"
        return name

    def update_path(self, path):
        from os.path import join, isdir, isfile
        if path is None or path == "":
            return False
        path = abspath(realpath(expandvars(path)))
        fullpath = join(path, self.name)
        if not isdir(path) or not isfile(fullpath):
            return False
        self.exists = True
        self.path = dirname(path)
        return True

    def full_path(self):
        """return the full path"""
        from os.path import join
        fullpath = join(self.path, self.name)
        return fullpath

class ExtensionList:
    """Tiny Core Extension List"""
    import re
    _re_KERNEL = re.compile('KERNEL')
    # TODO: put the download extension and download deps on this list?
    # can have download_extension and download_dep on Extension, with download_extensions and download_deps here?
    # or could have all of it here, to reduce the amount of connections to the servers?
    # Depends on how we handle the downloads. if we just call wget, we can stack them.
    # Not sure how to reuse the connection in python...

    @staticmethod
    def tc_kernel(major, arch):
        kernels = dict({
            '7': '4.2.9-tinycore',
            '6': '3.16.6-tinycore',
            '5': '3.8.13-tinycore',
            '4': '3.0.21-tinycore'
        })
        if major not in kernels:
            return None
        kernel = kernels[major]
        if arch == "x86_64":
            kernel += "64"
        return kernel

    # TODO: have the extensionlist hide the -KERNEL -<kernel> exchange. Need to implement... but how? maybe the by reference dict...
    def __init__(self,
        version = "7",
        arch = "x86",
        kernel = "4.2.9-tinycore"
        mirror = "http://tinycorelinux.net",
    ):
        self.kernel = kernel.strip()
        self.mirror = mirror.strip().rstrip("/")
        self.version = version.strip()
        self.arch = arch.strip()
        self._kernel_re = None
        self.extensions = dict()
        self.extension_bases = set()

        # Update Kernel if needed.
        kernel = ExtensionList.tc_kernel(version, arch)
        if kernel != self.kernel:
            self.kernel = kernel

    def __iter__(self):
        return iter(self.extensions)

    def __len__(self):
        return len(self.extensions)

    def make_basename(self, name):
        import re
        if self._kernel_re is None:
            self._kernel_re = re.compile(self.kernel)
        return re.sub(self._kernel_re, 'KERNEL', name)

    def make_tczname(self, name):
        import re
        return re.sub(ExtensionList._re_KERNEL, self.kernel, name)

    def append(self, extension):
        """Add a string extension to the list"""
        if extension is None or extension == "":
            return
        raw_ext = Extension(extension)
        if raw_ext is None or raw_ext.name == "":
            return
        self.add_extension(raw_ext)

    def add_extension(self, raw_ext):
        """Add an Extension to the list"""
        if raw_ext is None or raw_ext.name == "":
            return
        basename = self.make_basename(raw_ext.name)
        tczname = self.make_tczname(raw_ext.name)
        if (
            basename in self.extension_bases or
            tczname in self.extensions
        ):
            return
        raw_ext.name = tczname
        self.extensions[tczname] = raw_ext
        self.extension_bases.add(basename)

    def extend(self, ext_list):
        """Extend this Extension List with the passed in List"""
        for e in ext_list:
            self.append(e)

    def update_extensions(self, ExtList):
        for k,v in ExtList.extensions.items():
            self.add_extension(v)

    def discard_extension(self, raw_ext):
        if raw_ext is None:
            return
        basename = self.make_basename(raw_ext.name)
        tczname = self.make_tczname(raw_ext.name)
        self.extension_bases.discard(basename)
        if tczname in self.extensions:
            del self.extensions[tczname]

    def discard(self, ext):
        raw_ext = Extension(ext)
        self.discard_extension(raw_ext)

    def download_extension(self, raw_ext):
        mirror = "/".join(self.mirror, self.version += ".x", self.arch, "tcz")
        pass # download all related extension files from self.mirror

    def extend_deps(self, raw_ext):
        if raw_ext.exists: # nope. wrong. Nothing to check and say we're done actually...
            return
        pass # read in the raw_ext .dep file (if .exists), and extend the List with it

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

    opts.add_argument(
        "config", default=default_config,
        help="Specify config file for remaster operation")
    opts.add_argument(
        "--output", "-o", type=existing_dir, help="output directory and/or file"
    )
    opts.add_argument(
        "--dry-run", "-n", action='store_true',
        help="Determine needed dependencies and stop")
    opts.add_argument(
        "--tinycore-version", "-t",
        help="Tiny Core Major Version to build against")
    opts.add_argument(
        "--tinycore-arch", "-a",
        help="CPU Architecture to build against")
    opts.add_argument(
        "--tinycore-kernel", "-k",
        help="Tiny Core Kernel Version to build against")

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
    #~ opts.add_argument(
        #~ # "--install-root", "-O", default="/mnt/remaster/",
        #~ "--install-root", "-O",
        #~ help=argparse.SUPPRESS)

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
    config = configparser.ConfigParser()
    try:
        config.read(vars(args)['config'])
    except configparser.Error:
        return None
    # Create the internal sections
    i = "install"
    if i not in config:
        config[i] = {}

    # Add the args to the config
    for k,v in vars(args).items():
        if v is not None:
            config[i][k] = str(v)

    # Update TC kernel and info if needed
    tc_release = '/usr/share/doc/tc/release.txt'
    if ("tinycore-version" not in config[i] or
        config[i]["tinycore-version"] is None
    ):
        # Default to TC 7.x
        config[i]["tinycore-version"] = "7"
        if isfile(tc_release):
            with open(tc_release) as f:
                for line in f:
                    tc_version = line.strip()
                    if tc_version == "":
                        continue
                    config[i]["tinycore-version"] = tc_version.split('.')[0]
    if ("tinycore-arch" not in config[i] or
        config[i]["tinycore-arch"] is None
    ):
        # Default to x86 (over x86_64)
        config[i]["tinycore-arch"] = "x86"
        if isfile(tc_release):
            shell = abspath(expandvars(realpath('/bin/sh')))
            config[i]["tinycore-arch"] = \
                subprocess.run(['file', shell],
                    check=True, stdout=subprocess.PIPE
                ).stdout
    kernel = Extension.tc_kernel(config[i]["tinycore-version"], config[i]["tinycore-arch"])
    if isfile(tc_release):
        kernel = \
            subprocess.run(['uname', '-r'],
                check=True, stdout=subprocess.PIPE
            ).stdout

    if (kernel is None and
        ("tinycore-kernel" not in config[i] or
        config[i]["tinycore-kernel"] is None)
    ):
        return None
    config[i]["tinycore-kernel"] = kernel

    # if no output, base off config filename, tc-version & arch, and curdir
    out_file = splitext(basename(config[i]["config"]))[0]
    out_file = "".join([
        out_file,
        "-",config[i]["tinycore-version"],
        "-",config[i]["tinycore-arch"],
        ".gz"
    ])
    if "output" not in config[i]:
        new_path = abspath(realpath(expandvars("./")))
        new_out = path_join(new_path, out_file)
        config[i]["output"] = new_out
    elif isdir(config[i]["output"]):
        # just update the file-name
        new_path = abspath(realpath(expandvars(config[i]["output"])))
        new_out = path_join(new_path, out_file)
        config[i]["output"] = new_out
    else:
        # otherwise, just make sure it's a full absolute path
        full_out = config[i]["output"]
        full_out = abspath(realpath(expandvars(full_out)))
        config[i]["output"] = full_out

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

def download_file(url, filename):
    if url is none or filename is none:
        return False
    import urlib.request
    import shutil
    with urllib.request.urlopen(url) as response, open(filename, 'wb') as out_file:
        shutil.copyfileobj(response, out_file)

def download_dot_dep(url,extension):
    if url is none or filename is none:
        return False
    # Need a TC Mirror to use...

# TODO: remove extensionize_names() if we use ExtensionList instead
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
        safe_ext = raw_ext.replace("KERNEL", extensionize_names.kernel).strip()
        if safe_ext == "":
            extensions.discard(raw_ext)
            continue
        if not safe_ext.endswith(".tcz"):
            safe_ext += ".tcz"
        if safe_ext == raw_ext:
            continue
        extensions.discard(raw_ext)
        extensions.add(safe_ext)
    return extensions

@static_var("kernel", "")
def recursive_dirs(dirs):
    """Get subdirs for given dirs

    Get all the sub directories of the passed in dirs, be they symlinks or not

    Args:
        dirs: list of directory paths, can be symlinks
    Returns:
        set: abspath of initial directories and subdirs with symlinks dereferenced
    """
    from os import listdir
    from os.path import join
    if recursive_dirs.kernel == "":
        recursive_dirs.kernel = _call_output('uname -r').strip()
    raw_dirs = set(dirs)
    safe_dirs = set()
    for raw_dir in raw_dirs.copy():
        safe_dir = realpath(abspath(expandvars(raw_dir)))
        if not isdir(safe_dir):
            raw_dirs.remove(raw_dir)
            continue
        safe_dirs.add(safe_dir)
        new_dirs = [join(safe_dir,datum) for datum in listdir(safe_dir) if datum != recursive_dirs.kernel]
        raw_dirs.remove(raw_dir)
        safe_dirs.update(recursive_dirs(new_dirs))
    return safe_dirs

# TODO: remove demote() if we don't use tce-load anymore
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

    Identify absolute dereferenced path to an extension, and pull in any
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
    from os import getuid, devnull

    if path_exts == None:
        path_exts = {}
    extensions.discard("")
    for raw_ext in extensions.copy():
        raw_ext.strip()
        if raw_ext in path_exts:
            continue
        if raw_ext == "":
            continue
        # Can't run tce-load as root user, so demote this call if needed
        with open(devnull, 'w') as FNULL:
            #FNULL = open(devnull, 'w')
            dl_cmd = ['tce-load', '-w', raw_ext]
            if (getuid() == 0):
                # these are the default values for tc:staff in TC
                # not 100% sure we need to modify the gid to work...
                subprocess.call(dl_cmd, stdout=FNULL, preexec_fn=demote(1001,50))
            else:
                subprocess.call(dl_cmd, stdout=FNULL)

        for t_dir in dirs:
            path_ext = join(t_dir, raw_ext)
            if not isfile(path_ext):
                continue
            path_exts[raw_ext] = path_ext
            dep = path_ext + ".dep"
            if isfile(dep):
                extensions.update(get_dot_deps(dep))
            break
        else:
            # Need to fail here, because we never found the extension
            print("\n\nERROR: Could not find extension: ", raw_ext,"\n")
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

    print("Writing onboot.lst")
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
        print("Creating copy2fs.flg")
        subprocess.call(['touch', copy2fs])
        return

    print("Writing copy2fs.lst")
    #extensions = copy2fs_exts.split(',')
    with open(copy2fs, 'w') as f:
        #for ext in extensions:
        for ext in copy2fs_exts:
            f.write('{0}\n'.format(ext))

def tc_bundle_path(dir_path, bundle):
    # cd dir_path; sudo find|sudo cpio -v -o -H newc|gzip -2 -v > bundle
    # advdef -z4 bundle
    from os.path import join
    from subprocess import Popen, PIPE
    gzip_lvl = 9
    subprocess.call(['mv', '-f', bundle, bundle + '.old'])
    if (subprocess.call('advdef >/dev/null 2>&1',shell=True) == 0):
        gzip_lvl = 2
    print("Packaging the init image, this can take a few moments...")
    retcode = 1
    # Make sure the top level directory has correct permissions
    subprocess.call(['sudo', 'chown', 'root:', dir_path])
    subprocess.call(['sudo', 'chmod', '0755', dir_path])
    dir_home = join(dir_path, 'home/tc')
    if (isdir(dir_home)):
        subprocess.call(['sudo', 'chown', '1001:50', dir_home])
    with open(bundle, 'w') as f:
        find = Popen(['sudo', 'find'], cwd=dir_path, stdout=PIPE)
        cpio = Popen(
            ['sudo','cpio','-mo','-H','newc'],
            cwd=dir_path, stdin=find.stdout, stdout=PIPE
        )
        gzip = Popen(['gzip', '-{}'.format(gzip_lvl)],
            cwd=dir_path, stdin=cpio.stdout, stdout=f
        )
        # Allow find to receive a SIGPIPE if cpio exits.
        find.stdout.close()
        cpio.stdout.close()
        gzip.communicate()
        # don't make a zombie process
        find.wait()
        cpio.wait()
        retcode = gzip.returncode
    if gzip_lvl == 2:
        print("Further compressing the init image with 'advdef', please wait...")
        subprocess.call(['advdef', '-z4', bundle])
    print("\nProcessed config into initrd file:\n\n    {0}\n".format(bundle))

def copy_extensions(dir_path, extensions):
    # Copy .tcz, .tcz.dep, .tcz.md5.txt, .tcz.list, and .tcz.info
    for ext in extensions:
        subprocess.call(
            "cp -fp {0} {0}.dep {0}.md5.txt {0}.list {0}.info {1} 2>/dev/null".\
            format(ext, dir_path),
            shell=True)

def copy_backup(raw_data, work_dir):
    from os.path import join, basename
    data_file = abspath(realpath(raw_data))
    if not isfile(data_file):
        return 1
    if (
        0 == subprocess.call(
            ['sudo', 'cp', '-fp',
            data_file,
            join(work_dir, 'mydata.tgz')]
        )
    ):
        return 0
    return 1

def extract_core(raw_core_path, work_dir):
    """Extract a core.gz into work directory

    Args:
        raw_core_path: path to core.gz file to extract
        work_dir: path to work_root
    """
    from subprocess import Popen, PIPE
    from os import getuid
    #~ if (getuid() != 0):
        #~ print("ERROR: extracting initrd requires super user permissions")
        #~ return 1
    safe_core_path = realpath(abspath(expandvars(raw_core_path)))
    if not isfile(safe_core_path):
        print("initrd file not found: {}".format(safe_core_path))
        return 1
    #zcat safe_core_path | sudo cpio -i -H newc -d -p work_dir;
    #~ subprocess.call(
        #~ 'zcat {0} | sudo cpio -i -H newc -d'.format(safe_core_path),
        #~ cwd=work_dir, shell=True
    #~ )
    zcat = Popen(['zcat', safe_core_path], stdout=PIPE)
    cpio = Popen(
        ['sudo','cpio','-mi','-H','newc','-d'],
        cwd=work_dir, stdin=zcat.stdout, stdout=PIPE, stderr=PIPE
    )
    # Allow zcat to receive a SIGPIPE if cpio exits.
    zcat.stdout.close()
    cpio.communicate()
    # don't make a zombie process
    zcat.wait()
    # do we need to | this with zcat.returncode ?
    retcode = cpio.returncode
    """
    output=`dmesg | grep hda`
    # becomes
    p1 = Popen(["dmesg"], stdout=PIPE)
    p2 = Popen(["grep", "hda"], stdin=p1.stdout, stdout=PIPE)
    p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
    output = p2.communicate()[0]
    p1.wait() # don't make zombies
    retcode = p2.returncode
    """
    # TODO (chazzam) determine if the extraction succeeded
    return retcode

def sudo_rmtree(path):
    """remove a path with sudo permissions

    Args:
        path: the path to delete
    """
    import subprocess
    subprocess.call(['sudo', 'rm', '-rf', path])

def main(argv=None):
    """Main function of script.

    processes command line args, config file, and carries out operations
    needed to build initrd image for booting with the needed file structure
    """
    from sys import argv as sys_argv
    from tempfile import mkdtemp
    from os.path import join, basename

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
        print("\n\nERROR: Could not process configuration file\n")
        return 1
    # Build current list of extensions (extensions + onboot)
    extension_list = ExtensionList(config["install"]["tinycore-kernel"])
    onboot_list = ExtensionList(config["install"]["tinycore-kernel"])
    copy2fs_list = ExtensionList(config["install"]["tinycore-kernel"])
    if "extensions" in config["install"]:
        extension_list.extend((config["install"]["extensions"]).split(','))
        #extension_list = extensionize_names(extension_list)
    if "onboot" in config["install"]:
        onboot_list.extend((config["install"]["onboot"]).split(','))
        #onboot_list = extensionize_names(onboot_list)
        extension_list.extend(onboot_list)
        print("\nOnboot extensions:\n{0}".format(', '.join(sorted(onboot_list))))
    if "copy2fs" in config["install"]:
        copy2fs_list.extend((config["install"]["copy2fs"]).split(','))
        if not ( len(copy2fs_list) == 1 and
          ("all" in copy2fs_list or "flag" in copy2fs_list)
          ):
            #copy2fs_list = extensionize_names(copy2fs_list)
            extension_list.extend(copy2fs_list)
    config["install"]["onboot"] = ','.join(onboot_list)
    config["install"]["copy2fs"] = ','.join(copy2fs_list)
    config["install"]["extensions"] = ','.join(extension_list)
    if "implicit_copy2fs" in config["install"]:
        # Don't include the implicit copy2fs extensions in the regular copy2fs
        # They are to be written to the copy2fs.lst, but not explicitly included
        # in the image.
        implicit_list = ExtensionList(config["install"]["tinycore-kernel"])
        implicit_list.extend(config["install"]["implicit_copy2fs"].split(','))
        #implicit_list = extensionize_names(implicit_list)
        config["install"]["implicit_copy2fs"] = ','.join(implicit_list)
        # We do want to print the implicit copy2fs extensions though, so update it now
        copy2fs_list.extend(implicit_list)
    if len(copy2fs_list) > 0:
        print("\nCopy to filesystem extensions:\n{0}".format(', '.join(sorted(copy2fs_list))))

    # Setup directory list default for extension searching
    dir_list = []
    if "extensions_local_dir" in config["install"]:
        dir_list = config["install"]["extensions_local_dir"].split(',')
    if isfile('/usr/share/doc/tc/release.txt'):
        # Append the system extension directory if running on a TC system
        dir_list.append(
            '/etc/sysconfig/tcedir/optional/upgrades',
            '/etc/sysconfig/tcedir/optional/'
        )
    config["install"]["extensions_local_dir"] = ','.join(dir_list)

    # Need to verify all of them end in .tcz
    # Need to build an absolute path to all of the extensions
    # Recursively determine all dependencies
        # Assume any extension in a local dir will have its .dep if it exists.
        # If any extension is never found, try to tce-load -w it
        # If still can't get an absolute path to everything, fail.
    # Build out the recursive list of directories to search now.
    print("\nBuilding recursive directory list...")
    safe_dirs = []
    for dir in dir_list:
        raw_dirs = recursive_dirs([dir])
        if len(raw_dirs) == 0:
            continue
        safe_dirs.extend(raw_dirs)
    # Get a flattened list of needed extensions
    print("Locating all extensions and dependencies...")
    import pdb;pdb.set_trace()
    extension_list = get_deps(safe_dirs, extension_list)
    print("\nIncluding extensions:\n{0}\n".format(
        ', '.join(sorted([basename(ext) for ext in extension_list]))
    ))

    if ("dry_run" in config["install"] and
        config.getboolean("install", "dry_run")
    ):
        return 0

    work_root = mkdtemp(prefix="remaster")
    work_dir = join(work_root, config["install"]["install_root"].lstrip('/'))
    work_install = join(work_dir, "optional/")
    # Create temp working directory for install, mkdir -p install_root 'tce'
    # setup folder structure within temp dir
    mkdir_p(work_install)

    # TODO (chazzam) verify the value is boolean, set false if not
    if "expand_tcz" not in config["install"]:
        config["install"]["expand_tcz"] = "no";

    # If combined_init, extract the init into work_root
    if "combined_init" in config["install"]:
        # TODO (chazzam) check the output and verify this succeeds.
        raw_init_path = config["install"]["combined_init"]
        ret = extract_core(raw_init_path, work_root)
        if ret != 0:
            return 1
    if config.getboolean("install", "expand_tcz"):
        print("Currently, expanding the tcz files is unsupported")
        return 1
    else:
        # copy everything to temp dir
        copy_extensions(work_install, extension_list)
    # write copy2fs.* and onboot.lst if needed
    write_onboot_lst(onboot_list, work_dir)
    if "copy2fs" in config["install"]:
        write_copy2fs(copy2fs_list, work_dir)
    if "mydata" in config["install"]:
        copy_backup(config["install"]["mydata"], work_dir)
    # squashfs the needful
    # gzip and advdef if it possible
    tc_bundle_path(work_root, config["install"]["output"])
    sudo_rmtree(work_root)
    return 0

"""allow unit testing and single exit point.

checking the __name__ before running allows inporting as a module, to the
python interactive interpreter and allows unit testing

calling sys.exit here may allow for single point of exit within the script
"""
if __name__ == '__main__':
    from sys import exit, hexversion
    if hexversion < 0x03050000:
        print("\n\nERROR: Requires Python 3.5.0 or newer\n")
        exit(1)
    exit(main())
