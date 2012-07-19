softlayer-object-storage-backup
===============================

SoftLayer's object storage backup script.  Works like rsync, but with our object storage service!

This script is indended to be used purely as a backup operation!
It will not make you run faster or jump higher.  It might save you from a really
bad day though.

Features
--------

* Rsync-like delta backups - only changed/new files are uploaded saving you time/bandwidth.
* Retention policies - deleted/updated files are kept for any desired length of time.  These can also be disabled.
* Threaded - Copying can always be the longest part, so backups are done in the background as 
file comparisions are being performed.
* MD5 support - Swift automatically sets a default hash (md5) for every object.  We support file
comparisions using this hash instead of time/size variance.
* Open source - MIT licensed (as is the object storage library).

Usage
=====

1. Download/install [object_storage](https://github.com/softlayer/softlayer-object-storage-python)
2. Download slbackup.py
3. run ```./slbackup.py --help```
4. run ```./slbackup.py --example > ~/.slbackup``` to get a config
5. run ```nano ~/.slbackup``` and put your credentials in there
6. run with the desired options.

I also [blogged about it](http://sldn.softlayer.com/blog/klandreth/Deglazing-slbackuppy-Usage-Object-Storage-Kitchen)

Known issues/limitations
========================

* Requires [python 2.6 or higher](https://github.com/softlayer/softlayer-object-storage-backup/issues/5).  Most modern distros should have this, but for the others, the 
[python26 package](http://dl.fedoraproject.org/pub/epel/5/x86_64/repoview/python26.html) should help those 
with production systems.
* 5GB file limitation: Swift does support [large files](http://swift.openstack.org/overview_large_objects.html) 
using Manifest files, but this script does not currently deal with this properly.  Not sure how to deal with
object fragments during file comparision.  Uploading and making the manifests is easy.
* Windows Support:  Tried to write the script in a way that supported windows.  However, it is not tested yet.
* Restoration: Restoring files is an operation left to the admin right now. 
[FUSE is handy](https://github.com/redbo/cloudfuse) for that kine of work.

