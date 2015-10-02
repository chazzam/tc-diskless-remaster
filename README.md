# tc-diskless-remaster
Script to help create remastered TC images for booting via PXE or USB  
It is known to work with TC4.x as of this writing, TC5.x and TC6.x are yet to be tested...  

Currently, it supports creating an addon image that will be added to the base TC core.gz.  

An example of booting this in a SYSLINUX config would be:  

    LABEL tc-asterisk
      menu label ^Asterisk (Tinycore)
      kernel /tc/vmlinuz
      append initrd=/tc/core.gz,/tc/asterisk.gz loglevel=3 superuser pretce=remaster  

It takes advantage of 'pretce' trying to mount a hard drive but not stopping if the drive isn't an actual volume to mimic a persistent tce within the initial initrd environment. So the value given to 'pretce' will be the path inside '/mnt/' where we will store all our files, in this case '/mnt/remaster/' Try not to use something that will actually exist as a device in the system...  

It supports Tiny Core's 'onboot.lst' functionality for loading extensions when the system boots. This is specified with an 'onboot=' line in the image config file. Care should be taken to only list the top level extensions and none of their dependencies if speed is a concern.  

It also supports Tiny Core's 'copy2fs' functionality via a 'copy2fs' line in the config file. 
If either 'all' or 'flag' is specified, then it will create a 'copy2fs.flg' file that will prompt Tiny Core to extract all extensions into the filesystem instead of mounting and symlinking like normal.
If a list of extensions is specified, then it will create a 'copy2fs.lst' file that will prompt Tiny Core to extract only the listed extensions into the filesystem.    

There are plans to add further support for the remaster that include integrating all the additional packages into the main core.gz, and for working without a config file. It may also support trying to do the copy2fs operation within the initial core.gz.  

The config file is read using Python's ConfigParser module, so features of that interface are supported. This includes the variable expansion of entries with the %()s syntax. e.g.  

    foo=bash.tcz
    bar=%(foo)s

Here is a breakdown of a config file:  

    [install]
    extensions = <comma separated list of tiny core extensions to download and include>
    onboot = <comma separated list of extensions to make available on boot>
      
    # install_root for TC4.x at least should be '/mnt/<path>' and <path> should the value of the 'pretce' kernel option
    install_root = <folder name inside the initrd in which to locate all the created files>
    output = <path or filename of output initrd file>
    copy2fs = <'all', 'flag', or a list of extensions to 'copy to filesystem' instead of mounting and symlinking>
    extensions_local_dir = <list of additional directories in which to search the system for tiny core extensions>

The script will automatically read in the '.dep' file of any extension it uses to find additional needed extensions that were not supplied in onboot, copy2fs, or extensions.
It will combine all extensions listed in onboot, copy2fs, and extensions. The entire list of extensions from all three parameters will be considered as the starting 'extension' list to include for finding dependencies.
It will use 'tce-load -w' to attempt to download all extensions needed, but will check other given directories with 'extensions_local_dir' before checking '/etc/sysconfig/tcedir/'. If you are currently depending on an extension to be included, but it is in the upgrades/ directory, you will need to either reboot and allow the upgrade to happen, or explicitly list the upgrades/ directory in 'extensions_local_dir' in order to use the updated version of the extension. It will also attempt to expand environment variables using Python's 'os.path.expandvars', so the dir can be something like '$HOME/tc/' and it should work. It will check the directories given recursively for extensions.
