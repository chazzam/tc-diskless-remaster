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

class Extension:
    """Tiny Core Extension"""
    def __init__(self, fullname):
        from os.path import dirname, basename
        # Get the filename before dereferencing symlinks
        self.name = basename(Extension.extensionize(fullname.strip()))
        self.path = ""
        self.exists = False
        self.update_path(dirname(fullname.strip()))
        self.depof = None

    def __str__(self):
        return self.full_path()

    @staticmethod
    def extensionize(name):
        name = name.strip()
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
        self.path = path
        return True

    def full_path(self):
        """return the full path"""
        from os.path import join
        fullpath = join(self.path, self.name)
        if self.path == "":
            fullpath = self.name
        return fullpath

class ExtensionList:
    """Tiny Core Extension List"""
    import re
    _re_KERNEL = re.compile('KERNEL')

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

    def __init__(self,
        version = "7",
        arch = "x86",
        kernel = "4.2.9-tinycore",
        mirror = "http://tinycorelinux.net"
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
        if kernel is not None and kernel != self.kernel:
            self.kernel = kernel

    def __iter__(self):
        return iter(self.extensions)

    def __len__(self):
        return len(self.extensions)

    def __str__(self):
        return ", ".join(sorted(self.extensions.keys()))

    def __contains__(self, item):
        # if item is <name>-KERNEL.tcz, convert to tczname and search
        raw_name = item
        if isinstance(item, Extension):
            raw_name = item.name
        tczname = self.make_tczname(raw_name)
        return tczname in self.extensions

    def make_basename(self, name):
        import re
        if self._kernel_re is None:
            self._kernel_re = re.compile(self.kernel)
        return re.sub(self._kernel_re, 'KERNEL', name.strip())

    def make_tczname(self, name):
        import re
        return re.sub(ExtensionList._re_KERNEL, self.kernel, name.strip())

    def add(self, raw_ext):
        """Add an Extension to the list"""
        if raw_ext is None:
            return
        if not isinstance(raw_ext, Extension):
            raw_ext = Extension(raw_ext.strip())
        if raw_ext.name == "":
            return
        safe_ext = raw_ext
        basename = self.make_basename(safe_ext.name)
        tczname = self.make_tczname(safe_ext.name)
        if (
            basename in self.extension_bases or
            tczname in self.extensions
        ):
            return
        safe_ext.name = tczname
        self.extensions[tczname] = safe_ext
        self.extension_bases.add(basename)

    def update(self, raw_other):
        """Update this Extension List with the passed in List()"""
        other = raw_other
        if isinstance(raw_other, ExtensionList):
            other = raw_other.extensions.values()
        for v in other:
            self.add(v)

    def discard(self, ext):
        if ext is None:
            return
        raw_ext = ext
        if not isinstance(raw_ext, Extension):
            raw_ext = Extension(ext.strip())
        basename = self.make_basename(raw_ext.name)
        tczname = self.make_tczname(raw_ext.name)
        self.extension_bases.discard(basename)
        if tczname in self.extensions:
            del self.extensions[tczname]

    def download_extension(self, ext, dest_dir):
        """Download requested extension from self.mirror

        Args:
            raw_ext: extension to download
            dest_dir: directory to save the extension

        Returns:
            Bool: True if downloaded, False if error
        """
        from os.path import join, isdir, isfile
        if ext is None or not isinstance(ext, Extension):
            return False
        if not isdir(dest_dir):
            return False

        def download_file(url, filename):
            if url is None or filename is None:
                return False
            import urllib.request
            import shutil
            from urllib.error import URLError
            try:
                with \
                    urllib.request.urlopen(url) as response, \
                    open(filename, 'wb') as out_file\
                :
                    shutil.copyfileobj(response, out_file)
            except URLError:
                return False
            if not isfile(filename):
                return False
            return True

        def download_files(url, path):
            # .dep is optional, extension and .md5.txt are required
            download_file(url + '.dep', path + '.dep')

            if (
                not download_file(url, path) or
                not download_file(url + '.md5.txt', path + '.md5.txt')
            ):
                return False
            return True

        def checksum_files(path):
            if not isfile(path) and not isfile(path + '.md5.txt'):
                return False
            # If no md5sum in path, accept it as-is and move on
            if (
                subprocess.run(['md5sum', '--version'],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                ).returncode != 0
            ):
                return True
            # Tiny Core uses '-s' for don't output anything, most everything
            # else uses '--status'. So don't pass either and just hide
            # stdout/stderr. the return code still shows result
            res = subprocess.run(['md5sum', '-c', path + '.md5.txt'],
                cwd=dirname(path),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            if (res.returncode == 0):
                return True
            return False

        mirror = "/".join([
            self.mirror.strip("/"),
            self.version + ".x",
            self.arch,
            "tcz"
        ])
        tczurl = "/".join([mirror, ext.name])
        tczpath = join(dest_dir, ext.name)

        # Download & checksum, if failed, try one more time.
        download_files(tczurl, tczpath)
        if checksum_files(tczpath):
            ext.update_path(dest_dir)
            return True
        download_files(tczurl, tczpath)
        if checksum_files(tczpath):
            ext.update_path(dest_dir)
            return True
        return False

    def update_with_deps(self, raw_ext):
        """Update list with dependencies from .dep file

        Args:
            raw_ext: the Extension to read deps for

        Returns:
            Bool: True if successful, False if error
        """
        if (
            raw_ext is None or
            not isinstance(raw_ext, Extension) or
            not raw_ext.exists
        ):
            return False
        from os.path import join, isfile
        dep = join(raw_ext.full_path(), ".dep")
        deps = set()
        # If there is no .dep file, then this extension has no deps
        if not isfile(dep):
            return True
        with open(dep) as f:
            for line in f:
                new_dep = line.strip()
                if new_dep == "":
                    continue
                deps.add(new_dep)
        self.update(deps)
        return True

    def localize_all_deps(self, dirs, dest_dir):
        """Get local absolute dereferenced paths to all needed extensions

        Identify absolute dereferenced path to an extension, and pull in any
        dependencies found in its .dep file as well

        Args:
            dirs: list of directories to search for extensions from this list
            dest_dir: location to download any non-local extensions

        Returns:
            Bool: True if all found, False if error or any not found
        """
        # seed needed with the current full set of extension names
        needed = set(self.extensions.keys())
        for t_dir in dirs:
            # Search each directory for our needed extensions
            for e in sorted(needed.copy()):
                ext = self.extensions[e]
                # If we have a path for this one, we don't need to find it.
                if ext.exists:
                    needed.discard(ext.name)
                    continue
                # If it isn't available at this path, move on
                if not ext.update_path(t_dir):
                    continue
                # Add any dependencies of this extension to the list
                print("Found {0} in {1}\n".format(ext.name, t_dir))
                self.update_with_deps(ext)
                needed.discard(ext.name)
        for e in needed:
            ext = self.extensions[e]
            print(
                "Downloading {0} from {1}\n".format(
                    ext.name, self.mirror)
            )
            if not self.download_extension(ext, dest_dir):
                print("\nERROR: extension {0} was ".format(ext.name) +
                    "not found locally and could not be downloaded\n"
                )
                return False
        if len(needed) >= 1:
            return self.localize_all_deps(dirs, dest_dir)
        return True

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
    opts.add_argument(
        "--tinycore-mirror", "-m",
        help="Tiny Core Kernel Mirror to download from")

    # TODO(cmoye) change default to False once the code supports it (version 2+)
    #~ opts.add_argument(
        #~ "--copy2fs-all", "-C", action='store_true', default=True,
        #~ help="Create 'copy2fs.flg' to force copy install for all extensions")
    #~ opts.add_argument(
        #~ "--copy2fs", "-c", nargs="*",
        #~ help="Create 'copy2fs.lst' to force copy install for given extensions")

    opts.add_argument(
        "--extensions-local-dir", "-e", type=existing_dir, nargs="*",
        help="Specify locally mounted locations to find extensions"
    )
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
        if k == "extensions_local_dir" and v is not None:
            config[i][k] = ",".join([",".join(v), config[i][k]])
        elif v is not None:
            config[i][k] = str(v)

    # Update TC kernel and info if needed
    tc_release = '/usr/share/doc/tc/release.txt'
    if ("tinycore_version" not in config[i] or
        config[i]["tinycore_version"] is None
    ):
        # Default to TC 7.x
        config[i]["tinycore_version"] = "7"
        if isfile(tc_release):
            with open(tc_release) as f:
                for line in f:
                    tc_version = line.strip()
                    if tc_version == "":
                        continue
                    config[i]["tinycore_version"] = tc_version.split('.')[0]
    if ("tinycore_arch" not in config[i] or
        config[i]["tinycore_arch"] is None
    ):
        # Default to x86 (over x86_64)
        config[i]["tinycore_arch"] = "x86"
        if isfile(tc_release):
            shell = abspath(expandvars(realpath('/bin/sh')))
            config[i]["tinycore_arch"] = \
                subprocess.run(['file', shell],
                    check=True, stdout=subprocess.PIPE
                ).stdout
    kernel = ExtensionList.tc_kernel(config[i]["tinycore_version"], config[i]["tinycore_arch"])
    if isfile(tc_release):
        kernel = \
            subprocess.run(['uname', '-r'],
                check=True, stdout=subprocess.PIPE
            ).stdout

    if (kernel is None and
        ("tinycore_kernel" not in config[i] or
        config[i]["tinycore_kernel"] is None)
    ):
        return None
    config[i]["tinycore_kernel"] = kernel

    if "tinycore_mirror" not in config[i] or config[i]["tinycore_mirror"] is None:
        config[i]["tinycore_mirror"] = "http://tinycorelinux.net"

    # if no output, base off config filename, tc-version & arch, and curdir
    out_file = splitext(basename(config[i]["config"]))[0]
    out_file = "".join([
        out_file,
        "-",config[i]["tinycore_version"],
        "-",config[i]["tinycore_arch"],
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

def recursive_dirs(dirs):
    """Get subdirs for given dirs

    Get all the sub directories of the passed in dirs, be they symlinks or not

    Args:
        dirs: list of directory paths, can be symlinks
    Returns:
        set: abspath of initial directories and subdirs with symlinks dereferenced
    """
    import re
    from os import walk
    from os.path import join
    from collections import OrderedDict
    kernel = re.compile('linux-[0-9.]+')
    hidden = re.compile('^\.')
    safe_dirs = OrderedDict()
    all_dirs = []
    for raw_dir in dirs.copy():
        safe_dir = realpath(abspath(expandvars(raw_dir)))
        if not isdir(safe_dir):
            continue
        safe_dirs[safe_dir] = 1

    for safe_dir in safe_dirs.keys():
        for root,d,f in walk(safe_dir, followlinks=True):
            all_dirs.append(root)
            for name in d:
                if re.match(kernel,name) or re.match(hidden,name):
                    d.remove(name)
                    continue
                all_dirs.append(join([root,name]))
    return all_dirs

def mkdir_p(path):
    # https://stackoverflow.com/questions/600268/mkdir-p-functionality-in-python
    import os, errno
    try:
        os.makedirs(path, exist_ok=True) # Python >=3.2
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
    with open(copy2fs, 'w') as f:
        for ext in copy2fs_exts:
            f.write('{0}\n'.format(ext))

# TODO: update to subprocess.run()
def tc_bundle_path(dir_path, bundle):
    # cd dir_path; find|cpio -v -o -H newc|gzip -2 -v > bundle
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
    subprocess.call(['chown', 'root:', dir_path])
    subprocess.call(['chmod', '0755', dir_path])
    dir_home = join(dir_path, 'home/tc')
    if (isdir(dir_home)):
        subprocess.call(['chown', '1001:50', dir_home])
    with open(bundle, 'w') as f:
        find = Popen(['find'], cwd=dir_path, stdout=PIPE)
        cpio = Popen(
            ['cpio','-mo','-H','newc'],
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

# TODO: update to subprocess.run() or maybe shutil.copy2
def copy_extensions(dir_path, extensions):
    # Copy .tcz, .tcz.dep, .tcz.md5.txt, .tcz.list, and .tcz.info
    for ext in extensions:
        subprocess.call(
            "cp -fp {0} {0}.dep {0}.md5.txt {0}.list {0}.info {1} 2>/dev/null".\
            format(ext, dir_path),
            shell=True)

# TODO: update to subprocess.run() or maybe shutil.copy2
def copy_backup(raw_data, work_dir):
    from os.path import join, basename
    data_file = abspath(realpath(raw_data))
    if not isfile(data_file):
        return 1
    if (
        0 == subprocess.call(
            ['cp', '-fp',
            data_file,
            join(work_dir, 'mydata.tgz')]
        )
    ):
        return 0
    return 1

# TODO: update to subprocess.run()
def extract_core(raw_core_path, work_dir):
    """Extract a core.gz into work directory

    Args:
        raw_core_path: path to core.gz file to extract
        work_dir: path to work_root
    """
    from subprocess import Popen, PIPE
    safe_core_path = realpath(abspath(expandvars(raw_core_path)))
    if not isfile(safe_core_path):
        print("initrd file not found: {}".format(safe_core_path))
        return 1
    zcat = Popen(['zcat', safe_core_path], stdout=PIPE)
    cpio = Popen(
        ['cpio','-mi','-H','newc','-d'],
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

def main(argv=None):
    """Main function of script.

    processes command line args, config file, and carries out operations
    needed to build initrd image for booting with the needed file structure
    """
    from sys import argv as sys_argv
    from tempfile import mkdtemp, TemporaryDirectory
    from os.path import join, basename
    from os import geteuid

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

    if (
        not config.getboolean("install", "dry_run") and
        geteuid() != 0
    ):
        print("\n\nERROR: Must run as super-user if not a dry-run\n")
        return 1

    # Build current list of extensions (extensions + onboot)
    extlist_args = {
        'version': config["install"]["tinycore_version"],
        'arch': config["install"]["tinycore_arch"],
        'kernel': config["install"]["tinycore_kernel"],
        'mirror': config["install"]["tinycore_mirror"]
    }

    extension_list = ExtensionList(**extlist_args)
    onboot_list = ExtensionList(**extlist_args)
    copy2fs_list = ExtensionList(**extlist_args)
    if "extensions" in config["install"]:
        extension_list.update((config["install"]["extensions"]).split(','))
    if "onboot" in config["install"]:
        onboot_list.update((config["install"]["onboot"]).split(','))
        extension_list.update(onboot_list)
        print("\nOnboot extensions:\n{0}".format(onboot_list))
    if "copy2fs" in config["install"]:
        copy2fs_list.update((config["install"]["copy2fs"]).split(','))
        if not ( len(copy2fs_list) == 1 and
          ("all" in copy2fs_list or "flag" in copy2fs_list)
          ):
            extension_list.update(copy2fs_list)
    config["install"]["onboot"] = str(onboot_list)
    config["install"]["copy2fs"] = str(copy2fs_list)
    config["install"]["extensions"] = str(extension_list)
    if "implicit_copy2fs" in config["install"]:
        # Don't include the implicit copy2fs extensions in the regular copy2fs
        # They are to be written to the copy2fs.lst, but not explicitly included
        # in the image.
        implicit_list = ExtensionList(**extlist_args)
        implicit_list.update(config["install"]["implicit_copy2fs"].split(','))
        config["install"]["implicit_copy2fs"] = str(implicit_list)
        # We do want to print the implicit copy2fs extensions though, so update it now
        copy2fs_list.update(implicit_list)
    if len(copy2fs_list) > 0:
        print("\nCopy to filesystem extensions:\n{0}".format(str(copy2fs_list)))

    # Setup directory list default for extension searching
    dir_list = []
    if "extensions_local_dir" in config["install"]:
        dir_list = config["install"]["extensions_local_dir"].split(',')
    if isfile('/usr/share/doc/tc/release.txt'):
        # Append the system extension directory if running on a TC system
        dir_list.extend([
            '/etc/sysconfig/tcedir/optional/upgrades',
            '/etc/sysconfig/tcedir/optional/'
        ])
    config["install"]["extensions_local_dir"] = ','.join(dir_list)

    # Build out the recursive list of directories to search now.
    print("\nBuilding recursive directory list...")
    safe_dirs = recursive_dirs(dir_list)
    print("Locating all extensions and dependencies...")

    # Create temp working directory for install
    work_root = TemporaryDirectory(prefix="remaster-") # Python >= 3.2
    work_dir = join(work_root.name, config["install"]["install_root"].lstrip('/'))
    work_install = join(work_dir, "optional/")
    # setup folder structure within temp dir
    mkdir_p(work_install)

    search_dirs = [work_install]
    search_dirs.extend(safe_dirs)
    if not extension_list.localize_all_deps(search_dirs, work_install):
        return 1
    print("\nIncluding extensions:\n{0}\n".format(extension_list))

    if config.getboolean("install", "dry_run"):
        return 0

    # TODO (chazzam) verify the value is boolean, set false if not
    if "expand_tcz" not in config["install"]:
        config["install"]["expand_tcz"] = "no";

    # If combined_init, extract the init into work_root
    if "combined_init" in config["install"]:
        # TODO (chazzam) check the output and verify this succeeds.
        raw_init_path = config["install"]["combined_init"]
        ret = extract_core(raw_init_path, work_root.name)
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
    tc_bundle_path(work_root.name, config["install"]["output"])
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
