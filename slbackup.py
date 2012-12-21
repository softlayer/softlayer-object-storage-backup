#!/usr/bin/python

""" SoftLayer object storage backup """

__author__ = "Kevin Landreth"
__copyright__ = "Copyright 2012, SoftLayer"
__credits__ = ["Kevin Landreth", "Kevin McDonald", "Chris Evans"]
__license__ = "MIT"
__version__ = "2.0"
__maintainer__ = "Kevin Landreth"
__email__ = "klandreth@softlayer.com"
__status__ = "Production"
__agent__ = 'softlayer/slbackup-%s' % __version__

import os
import sys
import time
import logging
import logging.config
import ConfigParser
from copy import copy
from hashlib import md5
from multiprocessing import Pool, cpu_count, Process
from multiprocessing import Manager
from itertools import repeat

try:
    import object_storage
except ImportError:
    print "ERROR: You need the latest object storage bindings from github:"
    print "  https://github.com/softlayer/softlayer-object-storage-python"
    print "  or pip install softlayer-object-storage"
    object_storage = None


try:
    import resource
except ImportError:
    # well, must be windows, assume an 4Kb slab
    # regardless if long mode is supported
    def default_page():
        return 4 * 1024
    resource = object()
    resource.getpagesize = default_page


class KeyboardInterruptError(Exception):
    pass


class SkippedFile(Exception):
    pass


class Swackup(object):
    _DEFAULT_RETENTION = 30
    _DEFAULT_CHECKHASH = False
    _DEFAULT_CONFIG = os.path.expanduser('~/.slbackup')
    _DEFAULT_THREADS = cpu_count()
    _DEFAULT_DC = 'dal05'
    _DEFAULT_USE_PRIVATE = False
    _DEFAULT_OS_BUFLEN = resource.getpagesize()

    DATE_FORMATS = [
        "%a, %d %b %Y %H:%M:%S %Z",
        "%a, %d %b %Y %H:%M:%S.%f %Z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d"
    ]

    def __init__(self, options):
        if not isinstance(options, dict):
            options = options.__dict__

        # config parser expects str() values
        defaults = {
                'datacenter': self._DEFAULT_DC,
                'internal': self._DEFAULT_USE_PRIVATE,
                'checksum': self._DEFAULT_CHECKHASH,
                'threads': self._DEFAULT_THREADS,
                'retention': self._DEFAULT_RETENTION,
                }
        for k, v in defaults.iteritems():
            if k == 'example':
                continue
            defaults[k] = str(v)

        defaults['username'] = 'MISSING'
        defaults['apikey'] = 'MISSING'

        if options['example']:
            c = ConfigParser.SafeConfigParser()
            c.add_section("slbackup")
            for k, v in defaults.iteritems():
                if k in ['container', 'source', 'example', 'config']:
                    continue
                c.set("slbackup", k, v)

            c.add_section("loggers")
            c.set("loggers", "keys", "root")

            c.add_section("handlers")
            c.set("handlers", "keys", "defhandler")

            c.add_section("formatters")
            c.set("formatters", "keys", "defformatter")

            c.add_section("logger_root")
            c.set("logger_root", "level", "NOTSET")
            c.set("logger_root", "handlers", "defhandler")

            c.add_section("handler_defhandler")
            c.set("handler_defhandler", "class", "StreamHandler")
            c.set("handler_defhandler", "level", "WARN")
            c.set("handler_defhandler", "formatter", "defformatter")
            c.set("handler_defhandler", "args", "(sys.stdout,)")

            c.add_section("formatter_defformatter")
            c.set("formatter_defformatter", "format",
                    "%(asctime)s|%(levelname)s|%(name)s %(message)s")
            c.set("formatter_defformatter", "datefmt", "")
            c.set("formatter_defformatter", "class", "logging.Formatter")

            c.write(sys.stdout)
            sys.exit(0)

        c = ConfigParser.SafeConfigParser(defaults)
        c.read(options['config'])

        self.username = c.get('slbackup', 'username')
        self.apikey = c.get('slbackup', 'apikey')
        self.dc = c.get('slbackup', 'datacenter')
        self.use_private = c.getboolean('slbackup', 'internal')
        self.checkhash = c.getboolean('slbackup', 'checksum')
        self.retention = c.get('slbackup', 'retention')
        self.threads = c.getint('slbackup', 'threads')
        self.excludes = []
        self.source = options.get('source')
        self.container = options.get('container')
        self.prefix = options.get('prefix', '')

        self.auth_url = None
        self.token = None
        self.url = None

        if c.has_option('slbackup', 'auth_url'):
            self.auth_url = c.get('slbackup', 'auth_url')
            logging.warn("Overriding auth url to %s", self.auth_url)

        # CLI overrides config file
        if options.get('datacenter', None) is not None:
            self.dc = options['datacenter']
            logging.warn("Override: Using datacenter: %s", self.dc)

        if options.get('internal', None) is not None:
            self.use_private = True
            logging.warn("Override: Enabling private backend "
                "network endpoint.")

        if options.get('checksum', None) is not None:
            self.checkhash = True
            logging.warn("Override: Enabling checksum validation.")

        if options.get('retention', None) is not None:
            self.retention = options['retention']
            logging.warn("Override: Setting retention days to %d",
                    self.retention)

        if options.get('threads', None) is not None:
            self.threads = options['threads']
            logging.warn("Override: Setting threads to %d", self.threads)

        if options.get('xf', None) is not None:
            with open(options['xf'], 'r') as x:
                for l in x.readlines():
                    self.excludes.append(l.strip())

        if options.get('exclude', None) is not None:
            for x in options['exclude']:
                self.excludes.append(x)

        logging.info("Excluding: %s", self.excludes)

        if options.get('test'):
            try:
                self.authenticate()
            except Exception, e:
                print "Something is wrong: %s" % e
            else:
                print "Appears to work!"
                print "URL:", self.url
                print "Token:", self.token

            sys.exit(0)

    @property
    def retention(self):
        return self._retention

    @retention.setter
    def retention(self, value):
        intval = None
        unit = None

        # see if they passed in just a numeric string
        # if so, set it to the number of days
        try:
            intval = int(value)
            unit = 'd'
        except ValueError:
            unit = value[-1]
            intval = int(value[:-1])

        units = {
            's': 1,
            'm': 60,
            'h': 60 * 60,
            'd': 24 * 60 * 60,
            'w': 7 * 24 * 60 * 60,
        }

        if unit not in units:
            raise ValueError("Invalid time value '%s'. Must be one of %s"
                    % (unit, ', '.join(units.keys()),))

        self._retention = units[unit] * int(intval)

    def try_datetime_parse(self, datetime_str):
        """
        Tries to parse the datetime and return the UNIX epoc version of time

        returns timestamp(int) or None
        """
        mtime = None
        if datetime_str:
            for fmt in self.DATE_FORMATS:
                try:
                    mtime_tuple = time.strptime(datetime_str, fmt)
                    mtime = time.mktime(tuple(mtime_tuple))
                except ValueError:
                    pass
                else:
                    break
        return mtime

    def _setup_client(self):
        use_network = 'private' if self.use_private else 'public'

        object_storage.consts.USER_AGENT = __agent__
        self.client = object_storage.get_client(
            self.username,
            self.apikey,
            datacenter=self.dc,
            network=use_network,
            auth_url=self.auth_url)

    def authenticate(self):
        self._setup_client()

        logging.info("Logging in as %s in %s",
                self.username, self.dc)

        self.client.conn.auth.authenticate()

        self.url = self.client.get_url()
        self.token = copy(self.client.conn.auth.auth_token)

        self.client.set_storage_url(self.url)

    def get_container(self, name=None):
        if name is None:
            name = self.container

        return self.client[name]

    def get_object_name(self, name):
        return "%s%s" % (self.prefix, name)

    def new_revision(self, _from, marker):
        l = logging.getLogger("new_revision")
        if self.retention < 1:
            l.warn("Retention disabled for %s", _from)
            return None

        # copy the file to the -revisions container so we don't
        # pollute the deleted items list.  Not putting revisions
        # in a seperate container will lead to an ever growing
        # list slowing down the backups

        _rev_container = "%s-revisions" % self.container

        safe_filename = encode_filename(_from)
        new_file = safe_filename + "/" + marker

        container = self.get_container()
        revcontainer = self.get_container(name=_rev_container)
        revcontainer.create()

        obj = container.storage_object(safe_filename)
        rev = revcontainer.storage_object(new_file)

        if obj.exists():
            l.info("Copying %s to %s", obj.name, rev.name)
            rev.create()
            obj.copy_to(rev)
            self.delete_later(rev)

    def delete_later(self, obj):
        """ lacking this in the bindings currently, work around it.
            Deletes a file after the specified number of days
        """
        l = logging.getLogger("delete_later")
        when = int(time.time()) + self.retention
        l.debug("Setting retention(%d) on %s", when, obj.name)

        headers = {
            'X-Delete-At': str(when),
            'Content-Length': '0'}
        obj.make_request('POST', headers=headers)

    def create_directory(self, item):
        l = logging.getLogger("create_directory")

        safe_dir = encode_filename(item)
        l.info("Creating %s", self.get_object_name(safe_dir))

        container = app.get_container()
        obj = container.storage_object(self.get_object_name(safe_dir))
        obj.content_type = 'application/directory'
        obj.create()

        return True

    def upload_file(self, _file, failed=False):
        l = logging.getLogger('upload_file')
        container = self.get_container()

        target = self.get_object_name(encode_filename(_file))

        try:
            obj = container.storage_object(target)
            l.info("Uploading file %s", obj.name)
            chunk_upload(obj, _file)
            l.debug("Finished file %s ", obj.name)
        except (OSError, IOError), e:
            # For some reason we couldn't read the file, skip it but log it
            l.exception("Failed to upload %s. %s", _file, e)
            raise SkippedFile(_file)
        except Exception, e:
            if failed:
                l.error("Couldn't upload %s, skiping: %s", _file, e)
                raise SkippedFile(_file)
            else:
                l.error("Failed to upload %s, requeueing. Error: %s", _file, e)
                # in case we got disconnected, reset the container
                self.authenticate()
                return self.upload_file(_file, failed=True)
        else:
            return True

        return False

    def delete_file(self, obj, failed=False):
        l = logging.getLogger("delete_file")
        l.info("Deleting %s", obj['name'])

        try:
            # Copy the file out of the way
            self.new_revision(obj['name'], obj.get('hash', 'deleted'))

            # then delete it as it no longer exists.
            rm = self.get_container().storage_object(obj['name'])
            rm.delete()
        except Exception, e:
            if not failed:
                l.exception("Failed to delete %s, requeueing. Error: %s",
                        obj['name'], e)
                # in case we got disconnected, reset the container
                self.authenticate()
                return self.delete_file(obj, failed=True)
            else:
                l.exception("Failed to upload %s. %s", obj['name'], e)
                raise SkippedFile(obj['name'])
        else:
            return True
        return False

    def process_file(self, job):
        """ returns if a file should be uploaded or not and
        if the file should be be marked as done"""
        l = logging.getLogger('process_file')

        try:
            _file, obj = job
        except ValueError:
            raise ValueError("Job not a tuple")

        def _do_timesize():
            oldsize = int(obj.get('size'))
            cursize = int(get_filesize(_file))
            curdate = int(os.path.getmtime(_file))
            oldtime = obj.get('last_modified')

            # there are a few formats, try to figure out which one safely
            oldtime = self.try_datetime_parse(oldtime)
            if oldtime is None:
                l.warn("Failed to figure out the time format, skipping %s",
                        _file)
                return False

            if cursize == oldsize and oldtime >= curdate:
                l.debug("No change in filesize/date: %s", _file)
                return False

            l.debug("Revised: SIZE:%s:%s DATE:%s:%s FILE:%s",
                    oldsize, cursize, oldtime, curdate, _file)
            return True

        def _do_checksum():
            l.debug("Checksumming %s", _file)

            oldhash = obj['hash']
            newhash = swifthash(_file)

            if oldhash == newhash:
                l.debug("No change in checksum: %s", _file)
                return False

            l.debug("Revised: HASH:%s:%s FILE:%s", oldhash, newhash, _file)
            return True

        compare = _do_timesize
        if app.checkhash:
            compare = _do_checksum

        upload_file = False
        try:
            if compare():
                # make a new copy, retention is handled there.  Start uploading
                # and then remove it so it doesn't get deleted
                self.new_revision(obj['name'], obj['hash'])
                upload_file = True
        except (OSError, IOError), e:
            l.error("Couldn't read file size skipping, %s: %s", _file, e)
            raise SkippedFile(_file)
        # Just because we can't read it doesn't mean we don't have
        # the permission, it could be a medium error in which case
        # don't delete the file, remove it from the remote object dict
        # so it doesn't get marked for deletion later on.  Even if
        # the file doesn't need backing up, remove it just the same
        return upload_file

    def process_directory(self, job):
        try:
            _dir, obj = job
        except ValueError:
            raise ValueError("Job not a tuple")

        if obj.get('content_type', None) == 'application/directory':
            logging.debug("Skipping directory %s", _dir)
            return False

        return True

    def __call__(self, item):
        try:
            self._worker(*item)
        except KeyboardInterrupt:
            raise KeyboardInterruptError()
        except SkippedFile:
            return 1
        except Exception, e:
            return e

        return 0

    def _worker(self, work, job):
        self._setup_client()

        if self.url:
            self.client.set_storage_url(self.url)

        if self.token:
            self.client.conn.auth.auth_token = self.token

        if not self.url or not self.token:
            self.authenticate()

        if work == 'stat':
            rt = self.process_file(job)
            if rt:
                rt = self.upload_file(job[0])
        elif work == 'dstat':
            rt = self.process_directory(job)
            if rt:
                rt = self.create_directory(job[0])
        elif work == 'delete':
            rt = self.delete_file(job)
        elif work == 'mkdir':
            rt = self.create_directory(job)
        elif work == 'upload':
            rt = self.upload_file(job)
        else:
            logging.fatal("Unknown work type: %s", work)

        return rt


def get_filesize(_f):
    if isinstance(_f, file):
        size = int(os.fstat(_f.fileno())[6])
    else:
        with open(_f) as data:
            size = int(os.fstat(data.fileno())[6])

    return size


def swifthash(_f):
    """ Compute md5 of the file for comparison """

    m = md5()
    with open(_f, 'rb') as data:
        for line in asblocks(data):
            m.update(line)

    return m.hexdigest()


def asblocks(_f, buflen=resource.getpagesize()):
    """Generator that yields buflen bytes from an open filehandle.
    Yielded bytes might be less buflen. """
    if not isinstance(_f, file):
        raise TypeError("First parameter must be an file object")

    try:
        while True:
            data = _f.read(buflen)
            if data:
                yield data
            else:
                break
    except IOError, e:
        logging.error("Failed to read %d bytes: %s", buflen, e)
        raise e


def encode_filename(string):
    string = str(string)
    uc = unicode(string, 'utf-8', 'replace')
    return uc.encode('ascii', 'replace')


def chunk_upload(obj, filename, headers=None):
    upload = obj.chunk_upload(headers=headers)
    with open(filename, 'rb') as _f:
        for line in asblocks(_f):
            upload.send(line)
        upload.finish()


def catalog_directory(app, files, directories):
    logging.info("Gathering local files")
    for root, dirnames, filenames in os.walk('.'):
        # Prune all excluded directories from the list
        for a in app.excludes:
            b, p = os.path.split(a)
            if p in dirnames:
                if len(b) < 1:
                    logging.debug("Pruning %s", a)
                    dirnames.remove(p)
                elif root.find('./' + b) == 0:
                    logging.debug("Pruning %s", a)
                    dirnames.remove(p)

        for _dir in dirnames:
            directories.append(os.path.relpath(os.path.join(root, _dir)))

        for _file in filenames:
            files.append(os.path.relpath(os.path.join(root, _file)))

    logging.info("Done gathering local files")


def catalog_remote(app, objects):
    logging.info("Grabbing remote objects")
    container = app.get_container()
    container.create()
    f = container.objects()
    while True:
        for d in f:
            props = dict(d.headers)
            props.update(dict(d.props))
            #props.update(dict(d.props['meta']))
            objects.update({d.name: props})

        try:
            logging.info("Grabbing %s", f[-1].name)
            f = container.objects(marker=f[-1].name)
        except:
            break

    logging.info("Objects %d", len(objects))


def delta_force_one(files, directories, remote_objects, prefix=''):
    fmt = "%s%%s" % prefix

    file_prefixes = dict(zip((fmt % encode_filename(d) for d in files), files))
    dir_prefixes = dict(zip((fmt % encode_filename(d) for d in directories), directories))
    prefixes = {}
    prefixes.update(file_prefixes)
    prefixes.update(dir_prefixes)

    f = set(file_prefixes.keys())
    d = set(dir_prefixes.keys())
    r = set(remote_objects.keys())
    a = set(list(f) + list(d))

    work = []
    #work = zip(repeat('upload'), f - r) + \
           #zip(repeat('mkdir'), d - r)

    work += zip(repeat('upload'),
        dict((k, prefixes[k]) for k in (f - r)).values())
    work += zip(repeat('mkdir'),
        dict((k, prefixes[k]) for k in (d - r)).values())

    for st in dict((k, prefixes[k]) for k in (f & r)).values():
        work.append(('stat', (st, remote_objects[st],),))

    for sd in dict((k, prefixes[k]) for k in (d & r)).values():
        work.append(('dstat', (sd, remote_objects[sd],),))

    # add the remote object directly to the delete queue
    for dl in (r - a):
        work.append(('delete', remote_objects[dl],))

    return work


def upload_directory(app):
    """ Uploads an entire local directory. """
    manager = Manager()
    directories = manager.list()
    files = manager.list()
    remote_objects = manager.dict()
    exit_code = 0

    app.authenticate()

    logging.debug("%s %s", app.token, app.url)

    logging.info("Starting harvesters")
    local = Process(target=catalog_directory,
            args=(app, files, directories,))
    remote = Process(target=catalog_remote,
        args=(app, remote_objects,))

    remote.start()
    local.start()

    logging.info("Waiting for harvest")
    local.join()
    remote.join()

    backlog = delta_force_one(files, directories, remote_objects,
            prefix=app.prefix)

    logging.debug("Backlog: %s", backlog)
    if app.threads:
        p = Pool(processes=app.threads)
        # remove client property as it can't be pickled
        app.client = None
        try:
            rs = p.map_async(app, backlog, 1)
            p.close()
            rs.wait()
            if not rs.successful():
                raise rs.get()

            p.join()
            codes = rs.get()
        except KeyboardInterrupt:
            logging.info("Trying to stop...")
            p.terminate()
            return 130
    else:
        codes = map(app, backlog)

    logging.info("Done backing up %s to %s", app.source, app.container)

    if any(codes):
        logging.warn("Backup completed, but with errors. Check the log")
        exit_code = 1

    return exit_code


if __name__ == "__main__":
    import optparse

    if not object_storage:
        sys.exit(1)

    # using argparse would have been preferred but that requires python >=2.7
    # ideally this will work in 2.5, but certianly 2.6
    args = optparse.OptionParser(
        'slbackup -s PATH -o CONTAINER [....]'
        "\n\n"
        'SoftLayer rsync-like object storage backup script')

    args.add_option('-s', '--source', nargs=1, type="str",
            help='The directory to backup', metavar="/home")
    args.add_option('-o', '--container', nargs=1, type="str",
            help='Container name to backup to.', metavar="backupContainer")
    args.add_option('-c', '--config', nargs=1, type="str",
            default=Swackup._DEFAULT_CONFIG,
            help='Configuration file containing login credintials.'
            ' Optional, but a configuration file must exist at %s' %
                    Swackup._DEFAULT_CONFIG,
                    metavar=Swackup._DEFAULT_CONFIG)
    args.add_option('--example', action="store_true", default=False,
            help="Print an example config and exit.")

    args.add_option('--test', action="store_true", default=False,
            help="Test authentication settings.")

    # config file overrides, optional
    oargs = optparse.OptionGroup(args, "Configuration parameters",
        "These parameters (besides config) can be specified in the"
        " configuration file."
        "Specifying them via the command line will override the config file")

    oargs.add_option('-r', '--retention', nargs=1, type="str",
            help='Days of retention to keep updated and deleted files.'
            ' This will create a backupContainer-revisions container.'
            ' Set to 0 to delete and overwrite files immediately.'
            ' (default: %s)' % Swackup._DEFAULT_RETENTION,
            metavar=Swackup._DEFAULT_RETENTION)

    oargs.add_option('-t', '--threads', nargs=1, type="int",
            help='Number of threads to spawn.'
            'The number spawned will be two times this number.'
            'If in doubt, the default of %d will be used, resulting'
            'in %d threads on this system.' % (
                Swackup._DEFAULT_THREADS,
                Swackup._DEFAULT_THREADS * 2),
                metavar=Swackup._DEFAULT_THREADS)

    oargs.add_option('-z', '--checksum', action='store_true',
            help='Use md5 checksums instead of time/size comparison. '
            '(default: %s)' % Swackup._DEFAULT_CHECKHASH)

    oargs.add_option('-d', '--datacenter', nargs=1, type='str',
            help="Datacenter of the container. "
            "A container will be created if it doesn't exist. "
            "(default: %s)" % Swackup._DEFAULT_DC,
            metavar=Swackup._DEFAULT_DC)

    oargs.add_option('-i', '--internal', action='store_true',
            help="Use SoftLayer's backend swift endpoint. "
            "Saves bandwidth if using it within the softlayer network. "
            "(default: %s)" % Swackup._DEFAULT_USE_PRIVATE)

    xargs = optparse.OptionGroup(args, "Exclusion options",
        "Exclude particular directories.  DO NOT include the trailin slash!"
        " Using both options in conjunction result in a concatinated list."
        )

    xargs.add_option("-x", "--exclude", action="append", metavar="DIR",
            help="This can be repeated any number of times.")
    xargs.add_option("--xf", "--exclude-from", nargs=1,
            type="str", default=None, metavar="FILE",
            help="File including a line seperated list of directories.")

    xargs.add_option("--prefix", "-p", nargs=1,
            type="str", default='', metavar="some/path/",
            help="Prefix all objects with speficied string.  "
            "Make sure to include the trailing slash but not the leading one. "
            "i.e --prefix static/imgs/ or --prefix some:pre:fix:")

    args.add_option_group(oargs)
    args.add_option_group(xargs)
    (opts, extra) = args.parse_args()

    app = Swackup(opts)

    if not hasattr(opts, 'source') or not opts.source:
        args.error("Missing parameter: --source")

    if not hasattr(opts, 'container') or not opts.container:
        args.error("Missing parameter: --container")

    logging.config.fileConfig(opts.config)
    os.chdir(app.source)
    code = upload_directory(app)
    sys.exit(code)
