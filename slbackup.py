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
from multiprocessing import Manager, Pool, cpu_count, TimeoutError
import Queue

try:
    import object_storage
except ImportError:
    print "ERROR: You need the latest object storage bindings from github:"
    print "  https://github.com/softlayer/softlayer-object-storage-python"
    sys.exit(1)

try:
    import resource
except ImportError:
    # well, must be windows, assume an 4Kb slab
    # regardless if long mode is supported
    _DEFAULT_OS_BUFLEN = 4 * 1024
else:
    _DEFAULT_OS_BUFLEN = resource.getpagesize()


class Application(object):
    _DEFAULT_RETENTION = 30
    _DEFAULT_CHECKHASH = False
    _DEFAULT_CONFIG = os.path.expanduser('~/.slbackup')
    _DEFAULT_THREADS = cpu_count()
    _DEFAULT_DC = 'dal05'
    _DEFAULT_USE_PRIVATE = False
    _DEFAULT_OS_BUFLEN = 1024

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
        self.retention = c.getint('slbackup', 'retention')
        self.threads = c.getint('slbackup', 'threads')
        self.excludes = []
        self.source = options.get('source')
        self.container = options.get('container')

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

    def authenticate(self):
        use_network = 'private' if self.use_private else 'public'

        object_storage.consts.USER_AGENT = __agent__
        client = object_storage.get_client(
            self.username,
            self.apikey,
            datacenter=self.dc,
            network=use_network,
            auth_url=self.auth_url)

        logging.info("Logging in as %s in %s",
                self.username, self.dc)
        client.conn.auth.authenticate()

        self.url = client.get_url()
        self.token = copy(client.conn.auth.auth_token)
        del client


def get_container(app, name=None):
    if name is None:
        name = app.container

    object_storage.consts.USER_AGENT = __agent__
    client = object_storage.get_client(
            app.username,
            app.apikey,
            auth_token=app.token,
            auth_url=app.auth_url)
    client.set_storage_url(app.url)

    return client[name]


def catalog_directory(app, directory, files, directories):
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
            directories.put(os.path.relpath(os.path.join(root, _dir)))

        for _file in filenames:
            files.put(os.path.relpath(os.path.join(root, _file)))

    logging.info("Done gathering local files")
    files.put(None)
    directories.put(None)


def catalog_remote(app, objects):
    logging.info("Grabbing remote objects")
    container = get_container(app)
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


def upload_directory(app):
    """ Uploads an entire local directory. """
    manager = Manager()
    directories = manager.Queue()
    files = manager.Queue()
    remote_objects = manager.dict()
    uploads = manager.Queue()
    deletes = manager.Queue()
    mkdirs = manager.Queue()

    app.authenticate()

    logging.debug("%s %s", app.token, app.url)

    if app.threads:
        threaded_harvestor(app, files, directories, remote_objects)
    else:
        serial_harvestor(app, files, directories, remote_objects)

    args = (app, files, directories, remote_objects, uploads, deletes, mkdirs,)

    if app.threads:
        threaded_processor(*args)
    else:
        serial_processor(*args)

    logging.info("Done backing up %s to %s", app.source, app.container)


def serial_harvestor(app, files, directories, remote_objects):
    catalog_directory(copy(app), app.source, files, directories)
    catalog_remote(copy(app), remote_objects)


def threaded_harvestor(app, files, directories, remote_objects):
    pool = Pool(app.threads)

    logging.info("Starting harvesters")

    local = pool.apply_async(catalog_directory,
            (copy(app), app.source, files, directories,))
    remote = pool.apply_async(catalog_remote,
        (copy(app), remote_objects,))

    pool.close()

    logging.info("Waiting for harvest")
    pool.join()

    if not local.successful():
        logging.error("Local processing encountered an error")
        try:
            local.get()
        except Exception, e:
            logging.exception(e)
            raise e

    if not remote.successful():
        logging.error("Remote processing encountered an error")
        try:
            remote.get()
        except Exception, e:
            logging.exception(e)
            raise e


def serial_processor(app, files, directories, remote_objects, uploads,
        deletes, mkdirs):
    l = logging.getLogger('serial_processor')

    l.info("Processing directories (%d)", directories.qsize())
    process_directories = IterUnwrap(process_directory,
            copy(app), remote_objects, mkdirs)
    map(process_directories, queue_iter(directories))
    mkdirs.put(None)

    l.info("Creating Directories")
    create_dir = IterUnwrap(create_directory, copy(app))
    map(create_dir, queue_iter(mkdirs))

    process_files = IterUnwrap(process_file,
            copy(app), remote_objects, uploads)
    map(process_files, queue_iter(files))
    uploads.put(None)

    l.info("Starting uploader")
    process_uploads = IterUnwrap(upload_file, copy(app), uploads)
    map(process_uploads, queue_iter(uploads))

    l.info("%d objects scheduled for deletion", len(remote_objects))
    for d in remote_objects.values():
        deletes.put(d)
    deletes.put(None)

    delete_files = IterUnwrap(delete_file, copy(app), deletes)
    map(delete_files, queue_iter(deletes))


def threaded_done_marker(results, queue):
    if isinstance(results, Exception):
        logging.exception(results)
    queue.put(None)


def threaded_processor(app, files, directories, remote_objects, uploads,
        deletes, mkdirs):
    l = logging.getLogger("threaded_processor")
    workers = Pool(app.threads)
    writers = Pool(app.threads)
    file_proc = None
    dir_proc = None
    upload_proc = None

    if directories.qsize() > 1:

        l.info("Processing %d directories", directories.qsize())
        dir_done = IterUnwrap(threaded_done_marker, mkdirs)
        process_directories = IterUnwrap(process_directory,
                copy(app), remote_objects, mkdirs)
        dir_proc = workers.map_async(process_directories,
                queue_iter(directories), app.threads, dir_done)

        l.info("Creating Directories")
        mkdir = IterUnwrap(create_directory, copy(app))
        writers.map_async(mkdir, queue_iter(mkdirs), app.threads)
    else:
        directories.get_nowait()

    if files.qsize() > 1:
        l.info("Processing files")
        file_done = IterUnwrap(threaded_done_marker, uploads)
        process_files = IterUnwrap(process_file,
                copy(app), remote_objects, uploads)
        file_proc = workers.map_async(process_files,
                queue_iter(files), 2, file_done)

    else:
        directories.get_nowait()

    l.info("Waiting to process files")

    #TODO wait for processing to finish
    while file_proc or dir_proc or upload_proc:
        l.info("Waiting for processing")
        if file_proc:
            try:
                file_res = file_proc.wait(1)
                file_proc.successful()
            except (TimeoutError, AssertionError):
                l.info("Still processing files")
            else:
                l.info("Done processing files")
                file_proc = None
                if isinstance(file_res, Exception):
                    raise

        if dir_proc:
            try:
                dir_res = dir_proc.wait(1)
            except TimeoutError:
                l.info("Still processing directories")
            else:
                l.info("Done processing directories")
                dir_proc = None
                if isinstance(dir_res, Exception):
                    raise

        if upload_proc:
            try:
                upload_proc.wait(1)
                upload_proc.successful()
            except (TimeoutError, AssertionError):
                l.info("Still processing uploads")
            else:
                l.info("Done processing uploads")
                upload_proc = None
        elif uploads.qsize() > 0:
            process_uploads = IterUnwrap(upload_file, copy(app), uploads)
            l.info("Starting uploader")
            upload_proc = writers.map_async(process_uploads,
                    queue_iter(uploads), app.threads)
            l.info("This didn't run right away")

    # After the readers have all exited, we know that remote_objects
    # contains the remaining files that should be deleted from
    # the backups.  Dump these into a Queue for the writers to take
    # care of.
    for d in remote_objects.values():
        deletes.put(d)
    deletes.put(None)
    logging.info("%d objects scheduled for deletion", deletes.qsize() - 1)
    delete_files = IterUnwrap(delete_file, copy(app), deletes)
    workers.map_async(delete_files, queue_iter(deletes))

    workers.close()
    writers.close()

    while (uploads.qsize() + mkdirs.qsize() + deletes.qsize()) > 0:
        l.info("Actions remaining:- uploading:%d mkdir:%d deletes:%d",
            directories.qsize(),
            files.qsize(),
            deletes.qsize(),
        )
        time.sleep(1)
    l.info("Cleaning up, letting pending items finish %d",
            (uploads.qsize() + mkdirs.qsize() + deletes.qsize()))
    workers.join()
    writers.join()


def encode_filename(string):
    string = str(string)
    uc = unicode(string, 'utf-8', 'replace')
    return uc.encode('ascii', 'replace')


def process_directory(directory, app, remote_objects, mkdirs):
    _dir = directory
    safe_dir = encode_filename(_dir)

    if safe_dir in remote_objects and \
        remote_objects[safe_dir].get('content_type', None) == \
       'application/directory':
        del remote_objects[safe_dir]
        return

    if safe_dir in remote_objects:
        del remote_objects[safe_dir]

    mkdirs.put(safe_dir)


def create_directory(safe_dir, app):
    l = logging.getLogger("create_directory")
    l.info("Creating %s", safe_dir)

    container = get_container(app)
    obj = container.storage_object(safe_dir)
    obj.content_type = 'application/directory'
    obj.create()


def delete_file(obj, app, jobs):
    l = logging.getLogger("delete_file")
    l.info("Deleting %s", obj['name'])

    try:
        # Copy the file out of the way
        new_revision(app, obj['name'], obj.get('hash', 'deleted'))

        # then delete it as it no longer exists.
        rm = get_container(app).storage_object(obj['name'])
        rm.delete()
    except Exception, e:
        l.error("Failed to upload %s, requeueing. Error: %s", obj['name'], e)
        jobs.put(obj)
        # in case we got disconnected, reset the container
        app.authenticate()


def process_file(_file, app, objects, backlog):
    l = logging.getLogger('process_file')

    safe_filename = encode_filename(_file)

    # don't bother with checksums for new files
    if safe_filename not in objects:
        l.debug("Queued missing %s", safe_filename)
        backlog.put((_file, safe_filename,))
        return

    try:
        oldhash = objects[safe_filename].get('hash', None)

        oldsize = int(objects[safe_filename].get('size'))
        cursize = int(get_filesize(_file))
        curdate = int(os.path.getmtime(_file))
        oldtime = objects[safe_filename].get('last_modified')
    except (OSError, IOError), e:
        l.error("Couldn't read file size skipping, %s: %s", _file, e)
        del objects[safe_filename]
        return

    # there are a few formats, try to figure out which one safely
    for timeformat in ['%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S']:
        try:
            oldtime = time.mktime(time.strptime(oldtime,
                '%Y-%m-%dT%H:%M:%S.%f'))
        except ValueError:
            l.warn("Failed to figure out the time format, skipping %s",
                    _file)
            return
        else:
            break

    if cursize == oldsize and oldtime >= curdate and not app.checkhash:
        l.debug("No change in filesize/date: %s", _file)
        del objects[safe_filename]
        return
    elif app.checkhash:
        l.debug("Checksumming %s", _file)
        try:
            newhash = swifthash(_file)
        except (OSError, IOError), e:
            l.error("Couldn't hash skipping, %s: %s", _file, e)
            del objects[safe_filename]
            return

        if oldhash == newhash:
            l.debug("No change in checksum: %s", _file)
            del objects[safe_filename]
            return
        else:
            l.debug("Revised: HASH:%s:%s FILE:%s",
                    oldhash, newhash, safe_filename)
    else:
        l.debug("Revised: SIZE:%s:%s DATE:%s:%s FILE:%s",
                oldsize, cursize, oldtime, curdate, safe_filename)

    del objects[safe_filename]
    new_revision(app, _file, oldhash)
    backlog.put((_file, safe_filename,))


def new_revision(app, _from, marker):
    l = logging.getLogger("new_revision")
    if app.retention < 1:
        l.warn("Retention disabled for %s", _from)
        return None

    # copy the file to the -revisions container so we don't
    # pollute the deleted items list.  Not putting revisions
    # in a seperate container will lead to an ever growing
    # list slowing down the backups

    _rev_container = "%s-revisions" % app.container

    safe_filename = encode_filename(_from)
    fs = os.path.splitext(safe_filename)
    new_file = fs[0] + "_" + marker + fs[1]

    container = get_container(app)
    revcontainer = get_container(app, name=_rev_container)
    revcontainer.create()

    obj = container.storage_object(safe_filename)
    rev = revcontainer.storage_object(new_file)

    if obj.exists():
        l.debug("Copying %s to %s", obj.name, rev.name)

        rev.create()

        obj.copy_to(rev)
        delete_later(rev, app)


def delete_later(obj, app):
    """ lacking this in the bindings currently, work around it.
        Deletes a file after the specified number of days
    """
    l = logging.getLogger("delete_later")
    delta = int(app.retention) * 24 * 60 * 60
    when = int(time.time()) + delta
    l.debug("Setting retention(%d) on %s", when, obj.name)

    headers = {
        'X-Delete-At': str(when),
        'Content-Length': '0'}
    obj.make_request('POST', headers=headers)


def upload_file(job, app, jobs):
    l = logging.getLogger('upload_file')
    container = get_container(app)

    # job is a tuple
    _file, target = job

    try:
        obj = container.storage_object(target)
        l.info("Uploading file %s", obj.name)
        chunk_upload(obj, _file)
        l.debug("Finished file %s ", obj.name)
    except (OSError, IOError), e:
        # For some reason we couldn't read the file, skip it but log it
        l.error("Failed to upload %s. %s", _file, e)
    except Exception, e:
        l.error("Failed to upload %s, requeueing. Error: %s", _file, e)
        jobs.put((_file, target,))
        # in case we got disconnected, reset the container
        app.authenticate()
        container = get_container(app)


def chunk_upload(obj, filename, headers=None):
    upload = obj.chunk_upload(headers=headers)
    with open(filename, 'rb') as _f:
        for line in asblocks(_f):
            upload.send(line)
        upload.finish()


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


def asblocks(_f, buflen=_DEFAULT_OS_BUFLEN):
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


def queue_iter(queue):
    while True:
        try:
            item = queue.get()
        except Queue.Empty:
            break

        if item is None:
            break

        yield item


class IterUnwrap(object):
    def __init__(self, func, *args, **kwargs):
        self.func = func
        self.args = args
        self.kwargs = kwargs

    def __call__(self, item):
        a = (item,) + self.args
        return self.func(*a, **self.kwargs)


if __name__ == "__main__":
    import optparse

    # using argparse would have been preferred but that requires python >=2.7
    # ideally this will work in 2.5, but certianly 2.6
    args = optparse.OptionParser(
        'slbackup -s PATH -o CONTAINER [....]'
        "\n\n"
        'SoftLayer rsync-like object storage backup script',
        epilog="WARNING: this script uses mutliprocessing from python to "
        "reduce high latency HTTP round trip times."
        "It spawns on local file reader per thread (-t) and on "
        "uploader/deleter for every 2 readers."
        "Take this into consideration when specifying the -t option "
        "as the number is essentially doubled.")

    args.add_option('-s', '--source', nargs=1, type="str",
            help='The directory to backup', metavar="/home")
    args.add_option('-o', '--container', nargs=1, type="str",
            help='Container name to backup to.', metavar="backupContainer")
    args.add_option('-c', '--config', nargs=1, type="str",
            default=Application._DEFAULT_CONFIG,
            help='Configuration file containing login credintials.'
            ' Optional, but a configuration file must exist at %s' %
                    Application._DEFAULT_CONFIG,
                    metavar=Application._DEFAULT_CONFIG)
    args.add_option('--example', action="store_true", default=False,
            help="Print an example config and exit.")

    args.add_option('--test', action="store_true", default=False,
            help="Test authentication settings.")

    # config file overrides, optional
    oargs = optparse.OptionGroup(args, "Configuration parameters",
        "These parameters (besides config) can be specified in the"
        " configuration file."
        "Specifying them via the command line will override the config file")

    oargs.add_option('-r', '--retention', nargs=1, type="int",
            help='Days of retention to keep updated and deleted files.'
            ' This will create a backupContainer-revisions container.'
            ' Set to 0 to delete and overwrite files immediately.'
            ' (default: %s)' % Application._DEFAULT_RETENTION,
            metavar=Application._DEFAULT_RETENTION)

    oargs.add_option('-t', '--threads', nargs=1, type="int",
            help='Number of threads to spawn.'
            'The number spawned will be two times this number.'
            'If in doubt, the default of %d will be used, resulting'
            'in %d threads on this system.' % (
                Application._DEFAULT_THREADS,
                Application._DEFAULT_THREADS * 2),
                metavar=Application._DEFAULT_THREADS)

    oargs.add_option('-z', '--checksum', action='store_true',
            help='Use md5 checksums instead of time/size comparison. '
            '(default: %s)' % Application._DEFAULT_CHECKHASH)

    oargs.add_option('-d', '--datacenter', nargs=1, type='str',
            help="Datacenter of the container. "
            "A container will be created if it doesn't exist. "
            "(default: %s)" % Application._DEFAULT_DC,
            metavar=Application._DEFAULT_DC)

    oargs.add_option('-i', '--internal', action='store_true',
            help="Use SoftLayer's backend swift endpoint. "
            "Saves bandwidth if using it within the softlayer network. "
            "(default: %s)" % Application._DEFAULT_USE_PRIVATE)

    xargs = optparse.OptionGroup(args, "Exclusion options",
        "Exclude particular directories.  DO NOT include the trailin slash!"
        " Using both options in conjunction result in a concatinated list."
        )

    xargs.add_option("-x", "--exclude", action="append", metavar="DIR",
            help="This can be repeated any number of times.")
    xargs.add_option("--xf", "--exclude-from", nargs=1,
            type="str", default=None, metavar="FILE",
            help="File including a line seperated list of directories.")

    args.add_option_group(oargs)
    args.add_option_group(xargs)
    (opts, extra) = args.parse_args()

    app = Application(opts)

    if not hasattr(opts, 'source') or not opts.source:
        args.error("Missing parameter: --source")

    if not hasattr(opts, 'container') or not opts.container:
        args.error("Missing parameter: --container")

    logging.config.fileConfig(opts.config)
    os.chdir(app.source)
    upload_directory(app)
