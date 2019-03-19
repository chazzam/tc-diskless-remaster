#!/usr/bin/env python3
"""
Remaster a TinyCore for diskless operation
"""
import argparse, collections, configparser, datetime, glob
# import errno
import os, os.path, re
import shutil, subprocess, sys, tempfile
import urllib.error, urllib.request

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
        # Get the filename before dereferencing symlinks
        self.alt_names = []
        self.name = os.path.basename(
            Extension.extensionize(fullname.strip()))
        if '::=' in self.name:
            names = self.name.split('::=')
            self.name = names.pop(0).strip()
            self.alt_names.extend(names)
        if self.name == "" and len(self.alt_names) > 0:
            self.name = self.alt_names.pop(0)
        self.path = ""
        self.name_cycles = 0
        self.exists = False
        self.update_path(os.path.dirname(fullname.strip()))
        self.depof = None
        self.onboot = False
        self.copy2fs = False
        self.implicit = False

    def __str__(self):
        return self.full_path()

    def __lt__(self, other):
        return self.name < other.name

    @staticmethod
    def extensionize(name):
        name = name.strip()
        if name == "":
            return name
        if not name.endswith(".tcz"):
            name += ".tcz"
        return name

    def update_path(self, path):
        if path is None or path == "":
            return False
        path = os.path.abspath(
            os.path.realpath(os.path.expandvars(path)))
        fullpath = os.path.join(path, self.name)
        if not os.path.isdir(path) or not os.path.isfile(fullpath):
            self.exists = False
            return False
        self.exists = True
        self.path = path
        return True

    def full_path(self):
        """return the full path"""
        fullpath = os.path.join(self.path, self.name)
        if self.path == "":
            fullpath = self.name
        return fullpath

    def cycle_name(self):
        """move current name to back of alt_names, and first alt_name to name"""
        if len(self.alt_names) == 0:
            return False
        # Give up if we've cycled all the names
        if self.name_cycles == len(self.alt_names):
            return False
        self.alt_names.append(self.name)
        self.name = self.alt_names.pop(0).strip()
        self.name_cycles += 1
        return True

class ExtensionList:
    """Tiny Core Extension List"""
    _re_KERNEL = re.compile('KERNEL')

    @staticmethod
    def tc_kernel(major, arch):
        kernels = dict({
            '10': '4.19.10-tinycore',
            '9':  '4.14.10-tinycore',
            '8':  '4.8.17-tinycore',
            '7':  '4.2.9-tinycore',
            '6':  '3.16.6-tinycore',
            '5':  '3.8.13-tinycore',
            '4':  '3.0.21-tinycore'
        })
        if major not in kernels:
            return None
        kernel = kernels[major]
        if arch == "x86_64":
            kernel += "64"
        return kernel

    def __init__(self,
        version = "10",
        arch = "x86",
        kernel = "4.19.10-tinycore",
        mirror = "http://tinycorelinux.net"
    ):
        self.kernel = kernel.strip()
        self.mirror = mirror.strip().rstrip("/")
        self.version = version.strip()
        self.arch = arch.strip()
        self._kernel_re = None
        self.extensions = dict()
        self.extension_depnames = set()
        self.excluded_extensions = set()
        self.copy2fs_all = False

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

    def make_depname(self, name):
        if self._kernel_re is None:
            self._kernel_re = re.compile(self.kernel)
        return re.sub(self._kernel_re, 'KERNEL', name.strip())

    def make_tczname(self, name):
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
        depname = self.make_depname(safe_ext.name)
        tczname = self.make_tczname(safe_ext.name)
        if tczname in self.excluded_extensions:
            return
        if tczname in self:
            # Copy the onboot and copy2fs flags if set.
            # Make sure not to overwrite a True with a False.
            if safe_ext.onboot:
                self.extensions[tczname].onboot = True
            if safe_ext.copy2fs:
                self.extensions[tczname].copy2fs = True
            # set implicit False if any copy is False
            self.extensions[tczname].implicit &= safe_ext.implicit
            # Combine alt_names list if needed
            for name in safe_ext.alt_names:
                if name in self.extensions[tczname].alt_names:
                    continue
                self.extensions[tczname].alt_names.append(name)
            return
        safe_ext.name = tczname
        self.extensions[tczname] = safe_ext
        self.extension_depnames.add(depname)

    def exclude_extensions(self, raw_other):
        other = raw_other
        if isinstance(raw_other, ExtensionList):
            other = raw_other.extensions.values()
        exc_tcznames = set()
        exc_depnames = set()
        for e in other:
            exc_depnames.add(self.make_depname(e))
            exc_tcznames.add(self.make_tczname(e))
        # remove excludes from the depname list
        self.extension_depnames = \
            self.extension_depnames.difference(exc_depnames)
        # remove excludes from the extensions list, cheat by using set first
        self.excluded_extensions.update(exc_tcznames)
        set_exts=set(self.extensions.keys())
        set_exts = set_exts.difference(self.excluded_extensions)
        for e in self.extensions.copy().keys():
            if e not in set_exts:
                del self.extensions[e]

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
        depname = self.make_depname(raw_ext.name)
        tczname = self.make_tczname(raw_ext.name)
        self.extension_bases.discard(depname)
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
        if ext is None or not isinstance(ext, Extension):
            return False
        if not os.path.isdir(dest_dir):
            return False

        def download_file(url, filename):
            if url is None or filename is None:
                return False
            try:
                with \
                    urllib.request.urlopen(url) as response, \
                    open(filename, 'wb') as out_file\
                :
                    shutil.copyfileobj(response, out_file)
            except urllib.error.URLError:
                return False
            if not os.path.isfile(filename):
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
            if (
                not os.path.isfile(path) and
                not os.path.isfile(path + '.md5.txt')
            ):
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
                cwd=os.path.dirname(path),
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
        try_alts = True
        while try_alts:
            # Build URLs off current extension name (can be cycled)
            tczurl = "/".join([mirror, ext.name])
            tczpath = os.path.join(dest_dir, ext.name)

            # Download & checksum, if failed, try one more time.
            download_files(tczurl, tczpath)
            if checksum_files(tczpath):
                ext.update_path(dest_dir)
                return True
            download_files(tczurl, tczpath)
            if checksum_files(tczpath):
                ext.update_path(dest_dir)
                return True

            if not ext.cycle_name():
                try_alts = False
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
            return None
        dep = raw_ext.full_path() + ".dep"
        deps = set()
        # If there is no .dep file, then this extension has no deps
        if not os.path.isfile(dep):
            return deps
        with open(dep) as f:
            for line in f:
                new_dep = line.strip()
                if new_dep == "":
                    continue
                deps.add(new_dep)
        self.update(deps)
        return deps

    def recursive_dirs(self, dirs):
        """Get subdirs for given dirs

        Get all the sub directories of the passed in dirs, be they symlinks or not

        Args:
            dirs: list of directory paths, can be symlinks
        Returns:
            set: abspath of initial directories and subdirs with symlinks dereferenced
        """
        def has_tcz(sub_dir):
            glob_path = os.path.join(sub_dir, '**.tcz')
            tczs = len(set(map(os.path.dirname, glob.iglob(glob_path))))
            if tczs > 0:
                return True
            return False
        def expand_dirs(raw_dir):
            """Handle expanding $HOME under sudo"""
            user_home = os.path.expandvars('$HOME')
            if 'SUDO_USER' in os.environ:
                user_home = os.path.expanduser('~' + os.environ['SUDO_USER'])
            mod_dir = raw_dir.replace('$HOME', user_home)
            raw_dir = os.path.expandvars(raw_dir)
            mod_dir = os.path.expandvars(mod_dir)
            safe_dir = os.path.abspath(os.path.realpath(raw_dir))
            smod_dir = os.path.abspath(os.path.realpath(mod_dir))
            if not os.path.isdir(safe_dir):
                safe_dir = None
            if not os.path.isdir(smod_dir):
                smod_dir = None
            return (safe_dir, smod_dir)

        kernel = re.compile('linux-[0-9.]+')
        hidden = re.compile('^\.')
        my_tcz_dir = re.compile(re.escape(
            os.path.join(self.version + '.x', self.arch, 'tcz')
        ))

        arches = ['x86','x86_64','mips','armv6','armv7']
        if self.arch in arches:
            arches.remove(self.arch)
        tcz_dir_arch = re.compile(
            re.escape(os.path.join('.x', self.arch, 'tcz')))
        tcz_dir_arch_others = re.compile(
            os.path.join(
                re.escape('.x'),
                '(' + '|'.join(arches) + ')',
                'tcz'
            )
        )

        safe_dirs = collections.OrderedDict()
        all_dirs = []

        for raw_dir in dirs.copy():
            safe_dir = expand_dirs(raw_dir)
            for d in safe_dir:
                if d is not None:
                    safe_dirs[d] = 1

        for safe_dir in safe_dirs.keys():
            for root,d,f in os.walk(safe_dir, followlinks=True):
                if has_tcz(root):
                    all_dirs.append(root)
                for name in d:
                    if re.match(kernel,name) or re.match(hidden,name):
                        d.remove(name)
                        continue
                    sub_path = os.path.join(root,name)
                    if re.match(tcz_dir_arch_others, sub_path):
                        continue
                    if has_tcz(sub_path):
                        all_dirs.append(sub_path)
        for safe_dir in all_dirs.copy():
            if (
                re.match(tcz_dir_arch, safe_dir) and
                not re.match(my_tcz_dir, safe_dir)
            ):
                # Move extensions from another TC version to the end
                del all_dirs[safe_dir]
                all_dirs.append(safe_dir)
        return all_dirs

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
        needed = set(self.explicit_list())
        needed_next = set()
        for t_dir in dirs:
            # Search each directory for our needed extensions
            for ext in sorted(needed.copy()):
                # If we have a path for this one, we don't need to find it.
                if ext.exists:
                    needed.discard(ext)
                    continue
                # If it isn't available at this path, move on
                if not ext.update_path(t_dir):
                    continue
                # Add any dependencies of this extension to the list
                print("Found {0} in {1}".format(ext.name, t_dir))
                needed_next.update(self.update_with_deps(ext))
                needed.discard(ext)
        for ext in needed:
            print(
                "Downloading {0} from {1}".format(
                    ext.name, self.mirror)
            )
            if not self.download_extension(ext, dest_dir):
                print("\nERROR: extension {0} was ".format(ext.name) +
                    "not found locally and could not be downloaded\n"
                )
                return False
            needed_next.update(self.update_with_deps(ext))
        needed_next.discard(None)
        if len(needed) >= 1 or len(needed_next) >= 1:
            return self.localize_all_deps(dirs, dest_dir)
        return True

    def onboot_names(self):
        """Return list of names of onboot extensions"""
        ext_names = []
        for ext in self.extensions.values():
            if not ext.onboot:
                continue
            ext_names.append(ext.name)
        return ', '.join(sorted(ext_names))

    def copy2fs_names(self):
        """Return list of names of copy2fs extensions"""
        ext_names = []
        for ext in self.extensions.values():
            if not ext.copy2fs:
                continue
            ext_names.append(ext.name)
        return ', '.join(sorted(ext_names))

    def explicit_list(self):
        """Return list of non-implicit extensions"""
        exts = []
        for ext in self.extensions.values():
            if ext.implicit:
                continue
            exts.append(ext)
        return exts

    def write_onboot_lst(self, path):
        if len(self.onboot_names()) == 0:
            return

        print("Writing onboot.lst")
        onboot_lst = os.path.join(path, 'onboot.lst')
        with open(onboot_lst, 'w') as f:
            for ext in self.onboot_names().split(', '):
                f.write('{0}\n'.format(ext.strip()))

    def write_copy2fs(self, path):
        if len(self.copy2fs_names()) == 0 and not self.copy2fs_all:
            return

        copy2fs = os.path.join(path, 'copy2fs.lst')
        copy2fs_exts = self.copy2fs_names().split(', ')
        if self.copy2fs_all:
            copy2fs.replace(".lst", ".flg")
            copy2fs_exts = []

        print("Writing {0}".format(os.path.basename(copy2fs)))
        with open(copy2fs, 'w') as f:
            for ext in copy2fs_exts:
                f.write('{0}\n'.format(ext.strip()))


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
    dir_name = os.path.dirname(value)
    is_dir = (
        os.path.isdir(value) or
        os.path.isdir(dir_name) or
        dir_name == ""
    )
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
    is_file = os.path.isfile(value)
    if value == "" or not is_file:
        argparse.ArgumentTypeError(
            "Must specify an existing file for input")
    return value

def get_options(argv=None):
    """parse the commandline options.

    Check for all supported flags and do any available pre-processing
    """
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
        "--version-output", "-V",
        help="Version of generated output"
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
        help="Specify additional locally mounted locations to find extensions"
    )
    opts.add_argument(
        "--exclusive-extensions-local-dir", "-E", type=existing_dir, nargs="*",
        help="Exclusive locally mounted locations to find extensions"
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

def expand_dir(raw_dir):
    """Handle expanding $HOME under sudo"""
    user_home = os.path.expandvars('$HOME')
    if 'SUDO_USER' in os.environ:
        user_home = os.path.expanduser('~' + os.environ['SUDO_USER'])
    raw_dir = raw_dir.replace('$HOME', user_home)
    raw_dir = os.path.expandvars(raw_dir)
    safe_dir = os.path.abspath(os.path.realpath(raw_dir))
    return safe_dir

def read_configuration(args):
    """Read the configuration file and add in commandline parameters

    Read in the config file specified from command-line

    Pull in any relevant command-line parameters that should be stored for later
    """
    config = configparser.ConfigParser()
    my_config = expand_dir(vars(args)['config'])
    try:
        config.read(my_config)
    except configparser.Error:
        print("Config file {} couldn't be parsed\n\n".format(my_config))
        return None
    # Create the internal sections
    i = "install"
    d = "DEFAULT"
    if i not in config:
        config[i] = {}
    m = i
    if "sections" in config[i]:
        m = d
    exc_exts = ""
    # Add the args to the config
    for k,v in vars(args).items():
        if k == "extensions_local_dir" and v is not None:
            # Args has a list, but config has only strings
            if k not in config[d] and k in config[i]:
                config[d][k] = config[i][k]
            elif k not in config[d] and k not in config[i]:
                config[m][k] = ""
            x = v
            x.extend(config[m][k].split(","))
            config[m][k] = ",".join(x)
        elif k == "exclusive_extensions_local_dir" and v is not None:
            config[m][k] = ",".join(v)
            exc_exts = config[m][k]
        elif v is not None:
            config[m][k] = str(v)

    if exc_exts is None or exc_exts == "":
        exc_exts = ""
        config[m]["exclusive_extensions_local_dir"] = exc_exts
    else:
        config[m]["extensions_local_dir"] = exc_exts

    # Update TC kernel and info if needed
    tc_release = '/usr/share/doc/tc/release.txt'
    if ("tinycore_version" not in config[m] or
        config[m]["tinycore_version"] is None
    ):
        # Default to TC 7.x
        config[m]["tinycore_version"] = "7"
        if os.path.isfile(tc_release):
            with open(tc_release) as f:
                for line in f:
                    tc_version = line.strip()
                    if tc_version == "":
                        continue
                    config[m]["tinycore_version"] = tc_version.split('.')[0]
    if ("tinycore_arch" not in config[m] or
        config[m]["tinycore_arch"] is None
    ):
        # Default to x86 (over x86_64)
        config[m]["tinycore_arch"] = "x86"
        if os.path.isfile(tc_release):
            shell = expand_dir('/bin/sh')
            rfile = subprocess.run(['file', shell],
                check=True, stdout=subprocess.PIPE
            )
            rcut = subprocess.run(['cut','-d,','-f1'],
                input=rfile.stdout, stdout=subprocess.PIPE
            )
            rgrep = subprocess.run(['egrep','-o','[0-9]{2}'],
                input=rcut.stdout, stdout=subprocess.PIPE
            )
            my_arch = str(rgrep.stdout, 'utf-8').strip()
            if my_arch == "64":
                my_arch = "x86_64"
            else:
                my_arch = "x86"
            config[m]["tinycore_arch"] = my_arch
    kernel = ExtensionList.tc_kernel(
        config[m]["tinycore_version"], config[m]["tinycore_arch"])
    if os.path.isfile(tc_release) and (kernel is None or kernel == ""):
        kernel = str(
            subprocess.run(['uname', '-r'],
                check=True, stdout=subprocess.PIPE
            ).stdout, 'utf-8').strip()

    if ((kernel is None or kernel == "") and
        ("tinycore_kernel" not in config[m] or
        config[m]["tinycore_kernel"] is None)
    ):
        print("\nCouldn't determine kernel version\n\n")
        return None
    config[m]["tinycore_kernel"] = kernel

    if "tinycore_mirror" not in config[m] or config[m]["tinycore_mirror"] is None:
        config[m]["tinycore_mirror"] = "http://tinycorelinux.net"
        if os.path.isfile("/opt/tcemirror"):
            with open("/opt/tcemirror") as f:
                for line in f:
                    tc_mirror = line.strip()
                    if tc_mirror == "":
                        continue
                    config[m]["tinycore_mirror"] = tc_mirror

    config_name = os.path.splitext(
            os.path.basename(config[m]["config"]))[0]
    sections = [i]
    if "sections" in config[i]:
        sections = config[i]["sections"].split(",")
        config_name = None
    for s in sections.copy():
        s = s.strip()
        # if no output, base off config filename|section name, tc-version & arch, and curdir
        out_file = config_name
        if out_file is None:
            out_file = s
        d = datetime.date.today()
        ver = ""
        if (
            "version_output" in config[m] and
            config[m]["version_output"] is not None and
            config[m]["version_output"] != ""
        ):
            ver = "-".join([
                "",
                config[m]["version_output"].replace(" ", "-")
            ])
        out_file = "".join([
            out_file,
            ver,"_",
            config[m]["tinycore_version"],
            config[m]["tinycore_arch"],
            d.strftime("_%y%m%d"),
            ".gz"
        ])
        out_dir = ""
        if "output" in config[s]:
            out_dir = expand_dir(config[s]["output"])
        if out_dir == "":
            new_path = expand_dir("./")
            new_out = os.path.join(new_path, out_file)
            config[s]["output"] = new_out
        elif os.path.isdir(out_dir):
            # just update the file-name
            new_out = os.path.join(out_dir, out_file)
            config[s]["output"] = new_out
        else:
            # otherwise, just make sure it's a full absolute path
            config[s]["output"] = out_dir
        out_dir = os.path.dirname(config[s]["output"])
        if not os.path.isdir(out_dir):
            print("Config directory {} doesn't exist\n\n".format(out_dir))
            return None
        # Setup the exclusive local extensions directory in each section
        config[s]["exclusive_extensions_local_dir"] = exc_exts
        if exc_exts != "":
            config[s]["extensions_local_dir"] = exc_exts


    # TODO: Verify we have all the required fields if they weren't specified
    if ("install_root" not in config[m] or
        config[m]["install_root"] is None or
        config[m]["install_root"] == ""
    ):
        config[m]["install_root"] = "/tmp/tce"

    return config

# TODO: migrate to subprocess.run
def tc_bundle_path(dir_path, bundle):
    # cd dir_path; find|cpio -v -o -H newc|gzip -2 -v > bundle
    # advdef -z4 bundle
    gzip_lvl = 9
    if os.path.isfile(bundle):
        shutil.move(bundle, bundle + '.old')
    if (subprocess.run(
            ['advdef', '--version'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        ).returncode == 0
    ):
        gzip_lvl = 2
    print("Packaging the init image, this can take a few moments...")
    sys.stdout.flush()
    retcode = 1
    # Make sure the top level directory has correct permissions
    subprocess.run(['chown', 'root:', dir_path])
    subprocess.run(['chmod', '0755', dir_path])
    dir_home = os.path.join(dir_path, 'home/tc')
    dir_tmp = os.path.join(dir_path, 'tmp')
    if (os.path.isdir(dir_home)):
        subprocess.run(['chown', '-R', '1001:50', dir_home])
    if (os.path.isdir(dir_tmp)):
        subprocess.run(['chown', '-R', '1001:50', dir_tmp])
        #shutil.chown(dir_tmp, user="1001", group="50")
    with open(bundle, 'w') as f:
        find = subprocess.Popen(
            ['find'], cwd=dir_path, stdout=subprocess.PIPE)
        cpio = subprocess.Popen(
            ['cpio','-o','-H','newc'],
            cwd=dir_path, stdin=find.stdout, stdout=subprocess.PIPE
        )
        gzip = subprocess.Popen(['gzip', '-{}'.format(gzip_lvl)],
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
        sys.stdout.flush()
        subprocess.run(['advdef', '-z4', bundle])
    print("\nProcessed config into initrd file:\n\n    {0}\n".format(bundle))

def copy_extensions(dir_path, extensions):
    # Copy .tcz, .tcz.dep, .tcz.md5.txt, .tcz.list, and .tcz.info
    if not isinstance(extensions, ExtensionList):
        return False
    md5 = '.md5.txt'
    dep = '.dep'
    for ext in extensions.extensions.values():
        tczpath = ext.full_path()
        d_path = os.path.join(dir_path, ext.name)
        if tczpath == d_path:
            continue
        if not os.path.isfile(tczpath):
            # Skip implicit entries that weren't otherwise included
            continue
        shutil.copyfile(tczpath, d_path, follow_symlinks=True)
        shutil.copyfile(tczpath + md5, d_path + md5, follow_symlinks=True)
        # .dep files are only required to exist if there are dependencies
        if os.path.isfile(tczpath + dep):
            shutil.copyfile(
                tczpath + dep,
                d_path + dep,
                follow_symlinks=True
            )
    return True

def copy_backup(raw_data, tce_dir):
    data_file = expand_dir(raw_data)
    if not os.path.isfile(data_file):
        return False
    dest_data = os.path.join(tce_dir, 'mydata.tgz')
    if shutil.copy2(data_file, dest_data, follow_symlinks=True):
        return True
    return False

# TODO: update to subprocess.run()
def extract_core(raw_core_path, raw_root):
    """Extract a core.gz into work directory

    Args:
        raw_core_path: path to core.gz file to extract
        raw_root: path to work_root
    """
    safe_core_path = expand_dir(raw_core_path)
    if not os.path.isfile(safe_core_path):
        print("initrd file not found: {}".format(safe_core_path))
        return False
    if not os.path.isdir(raw_root):
        print("initrd extraction directory not found: {}".format(raw_root))
        return False
    zcat = subprocess.Popen(
        ['zcat', safe_core_path],
        stdout=subprocess.PIPE
    )
    cpio = subprocess.Popen(
        ['cpio','-mi','-H','newc','-d'],
        cwd=raw_root, stdin=zcat.stdout,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    # Allow zcat to receive a SIGPIPE if cpio exits.
    zcat.stdout.close()
    cpio.communicate()
    # don't make a zombie process
    zcat.wait()
    retcode = False
    if cpio.returncode == 0 and zcat.returncode == 0:
        retcode = True
    return retcode

def bundle_section(config=None, sec=None):
    if config is None or sec is None:
        return False
    if sec not in config:
        return False
    print(
        "Processing section:{0} from config:{1}".format(
            sec, config["install"]["config"]
        )
    )
    # Build current list of extensions (extensions + onboot)
    extlist_args = {
        'version': config["install"]["tinycore_version"],
        'arch': config["install"]["tinycore_arch"],
        'kernel': config["install"]["tinycore_kernel"],
        'mirror': config["install"]["tinycore_mirror"]
    }

    extension_list = ExtensionList(**extlist_args)
    if "extensions" in config[sec]:
        extension_list.update(config[sec]["extensions"].split(','))
    if "onboot" in config[sec]:
        onboot_list = ExtensionList(**extlist_args)
        onboot_list.update(config[sec]["onboot"].split(','))
        for ext in onboot_list.extensions.values():
            ext.onboot = True
        extension_list.update(onboot_list)
        print("\nOnboot extensions:\n{0}".format(onboot_list))
    if "copy2fs" in config[sec]:
        copy2fs_list = ExtensionList(**extlist_args)
        copy2fs_list.update(config[sec]["copy2fs"].split(','))
        for ext in copy2fs_list.extensions.values():
            ext.copy2fs = True
        if not ( len(copy2fs_list) == 1 and
          ("all" in copy2fs_list or "flag" in copy2fs_list)
          ):
            extension_list.update(copy2fs_list)
    if "exclude_extensions" in config[sec]:
        raw_exc = set(config[sec]["exclude_extensions"].split(","))
        safe_exc = set()
        for exc in raw_exc:
            exc = exc.strip()
            if exc is None or exc == "":
                continue
            safe_exc.add(exc)
        extension_list.exclude_extensions(safe_exc)
        # ~ onboot_list.exclude_extensions(safe_exc)
        # ~ copy2fs_list.exclude_extensions(safe_exc)
    config[sec]["onboot"] = extension_list.onboot_names()
    config[sec]["copy2fs"] = extension_list.copy2fs_names()
    config[sec]["extensions"] = str(extension_list)
    if "implicit_copy2fs" in config[sec]:
        # Don't include the implicit copy2fs extensions in the regular copy2fs
        # They are to be written to the copy2fs.lst, but not explicitly included
        # in the image.
        implicit_list = ExtensionList(**extlist_args)
        implicit_list.update(config[sec]["implicit_copy2fs"].split(','))
        for ext in implicit_list.extensions.values():
            ext.copy2fs = True
            ext.implicit = True
        config[sec]["implicit_copy2fs"] = str(implicit_list)
        # We do want to print the implicit copy2fs extensions though, so update it now
        extension_list.update(implicit_list)
    if len(extension_list.copy2fs_names()) > 0:
        print("\nCopy to filesystem extensions:\n{0}".format(extension_list.copy2fs_names()))

    # Setup directory list default for extension searching
    dir_list = []
    if "extensions_local_dir" in config[sec]:
        dir_list = config[sec]["extensions_local_dir"].split(',')
    if (
        os.path.isfile('/usr/share/doc/tc/release.txt') and
        config[sec]["exclusive_extensions_local_dir"] == ""
    ):
        # Append the system extension directory if running on a TC system
        dir_list.extend([
            '/etc/sysconfig/tcedir/optional/upgrades',
            '/etc/sysconfig/tcedir/optional/'
        ])
    config[sec]["extensions_local_dir"] = ','.join(dir_list)

    # Build out the recursive list of directories to search now.
    print("\nBuilding recursive directory list...")
    safe_dirs = extension_list.recursive_dirs(dir_list)
    print("Locating all extensions and dependencies...\n")

    # setup folder structure within temp dir
    # Clear the bundle folder if it exists, for each sec
    shutil.rmtree(config["install"]["work_bundle"], ignore_errors=True)
    os.makedirs(config["install"]["work_install"], exist_ok=True)

    search_dirs = [config["install"]["work_download"]]
    search_dirs.extend(safe_dirs)
    if not extension_list.localize_all_deps(
        search_dirs, config["install"]["work_download"]
    ):
        return False
    if len(extension_list.excluded_extensions) > 0:
        print(
            "\nExcluded extensions:\n{0}\n".format(
            ", ".join(sorted(extension_list.excluded_extensions))))
    print("\nIncluding extensions:\n{0}\n".format(extension_list))

    if config.getboolean(sec, "dry_run"):
        return True

    # TODO (chazzam) verify the value is boolean, set false if not
    if "expand_tcz" not in config[sec]:
        config[sec]["expand_tcz"] = "no";

    # If combined_init, extract the init into work_root
    if "combined_init" in config[sec]:
        raw_init_path = config[sec]["combined_init"]
        if not extract_core(raw_init_path, config["install"]["work_bundle"]):
            return False
    if config.getboolean(sec, "expand_tcz"):
        print("Currently, expanding the tcz files is unsupported")
        return False
    else:
        # copy everything to temp dir
        copy_extensions(config["install"]["work_install"], extension_list)
    # write copy2fs.* and onboot.lst if needed
    extension_list.write_onboot_lst(config["install"]["work_tce"])
    if "copy2fs" in config[sec]:
        extension_list.write_copy2fs(config["install"]["work_tce"])
    if "mydata" in config[sec]:
        copy_backup(config[sec]["mydata"], config["install"]["work_tce"])
    # squashfs the needful
    # gzip and advdef if it possible
    sys.stdout.flush()
    tc_bundle_path(config["install"]["work_bundle"], config[sec]["output"])
    return True

def main(argv=None):
    """Main function of script.

    processes command line args, config file, and carries out operations
    needed to build initrd image for booting with the needed file structure
    """
    if argv is None:
        argv = sys.argv
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
        os.geteuid() != 0
    ):
        print("\n\nERROR: Must run as super-user if not a dry-run\n")
        return 1

    # Create temp working directory for install
    work_root = tempfile.TemporaryDirectory(prefix="remaster-") # Python >= 3.2
    work_download = os.path.join(work_root.name, "download")
    os.makedirs(work_download, exist_ok=True)
    work_bundle = os.path.join(work_root.name, "bundle")
    work_tce = os.path.join(
        work_bundle,
        config["install"]["install_root"].lstrip('/')
    )
    work_install = os.path.join(work_tce, "optional/")
    config["install"]["work_download"] = work_download
    config["install"]["work_bundle"] = work_bundle
    config["install"]["work_tce"] = work_tce
    config["install"]["work_install"] = work_install

    sections = ["install"]
    if "sections" in config["install"]:
        sections = config["install"]["sections"].split(",")

    print(
        "\nUsing TinyCore {}{} and kernel {}\n".format(
            config["install"]["tinycore_version"],
            config["install"]["tinycore_arch"],
            config["install"]["tinycore_kernel"],
        )
    )
    for sec in sections.copy():
        sec = sec.strip()
        if not bundle_section(config, sec):
            return 1
    return 0

"""allow unit testing and single exit point.

checking the __name__ before running allows inporting as a module, to the
python interactive interpreter and allows unit testing

calling sys.exit here may allow for single point of exit within the script
"""
if __name__ == '__main__':
    if sys.hexversion < 0x03050000:
        print("\n\nERROR: Requires Python 3.5.0 or newer\n")
        sys.exit(1)
    sys.exit(main())
