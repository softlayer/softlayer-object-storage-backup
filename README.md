softlayer-object-storage-backup
===============================

*You can now install from pip!*  `pip install slbackup`

SoftLayer's object storage backup script.

This script is indended to be used purely as a backup operation!
It will not make you run faster or jump higher.  It might save you from a really
bad day though.


How it works
-------------

By default, the script uses time and size comparison based on the files mtime and upload time. The
entire file is transfered if either the size or the time differs.  If retention is enabled, the original file
is copied into a seperate container with the md5 sum inserted into the name before the changed file is uploaded.


Features
--------

* Whole file delta backups - only changed/new files are uploaded saving you time/bandwidth.
* Retention policies - deleted/updated files are kept for any desired length of time.  These can also be disabled.
* Threaded - Copying can always be the longest part, so backups are done in the background as 
file comparisons are being performed.
* MD5 support - Swift automatically sets a default hash (md5) for every object.  We support file
comparisons using this hash instead of time/size variance.
* Open source - MIT licensed (as is the object storage library).


Retention formats
-----------------

When specifying retention in the config file or _-r_ in the cli args, please be
advised of the new time formats below:

* time in days (1, 30, 15, etc)
* time specific unit (1s, 50d, 5w, 2h, 40m)
 * supported units: *s*econds, *m*inutes, *d*ays, *h*ours, *w*eeks
 * *cannot* stack time units (1d10m) - calculate it if you need this


Usage
=====

1. Download/install [object_storage](https://github.com/softlayer/softlayer-object-storage-python)
2. Download slbackup.py
3. run ```./slbackup.py --help```
4. run ```./slbackup.py --example > ~/.slbackup``` to get a config
5. run ```nano ~/.slbackup``` and put your credentials in there
6. run with the desired options.

I also [blogged about it] (http://sldn.softlayer.com/blog/klandreth/Deglazing-slbackuppy-Usage-Object-Storage-Kitchen)
with a bit more verbosity.

Known issues/limitations
========================

* Requires [python 2.6 or higher](https://github.com/softlayer/softlayer-object-storage-backup/issues/5).  Most modern distros should have this, but for the others, the 
[python26 package](http://dl.fedoraproject.org/pub/epel/5/x86_64/repoview/python26.html) should help those 
with production systems.
* 5GB file limitation: Swift does support [large files](http://swift.openstack.org/overview_large_objects.html) 
using Manifest files, but this script does not currently deal with this properly.  Not sure how to deal with
object fragments during file comparison.  Uploading and making the manifests is easy.
* Windows Support:  Tried to write the script in a way that supported windows.  However, it is not tested yet.
* Restoration: Restoring files is an operation left to the admin right now. 
[FUSE is handy](https://github.com/redbo/cloudfuse) for that kind of work.

