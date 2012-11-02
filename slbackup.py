#!/usr/bin/python


""" SoftLayer object storage backup """

__author__ = "Kevin Landreth"
__copyright__ = "Copyright 2012, SoftLayer"
__credits__ = ["Kevin Landreth", "Kevin McDonald", "Chris Evans"]
__license__ = "MIT"
__version__ = "1.2"
__maintainer__ = "Kevin Landreth"
__email__ = "klandreth@softlayer.com"
__status__ = "Production"

import os
import sys
import time
import logging
import logging.config
import ConfigParser
from copy import copy
from hashlib import md5
from multiprocessing import Manager, Process, cpu_count

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


def get_container(app, name=None):
    if name is None:
        name = app.container
    use_network = 'private' if app.use_private else 'public'
    logging.info("Logging in as %s in %s and getting container %s",
            app.username, app.dc, name)
    obj = object_storage.get_client(
            app.username, app.apikey, datacenter=app.dc, network=use_network)
    return obj[name]


def catalog_directory(app, directory, files, directories):
    logging.warn("Gathering local files")
    for root, dirnames, filenames in os.walk('.'):
        # Prune all excluded directories from the list
        for a in app.excludes:
            b, p = os.path.split(a)
            if p in dirnames:
                if len(b) < 1:
                    logging.info("Pruning %s", a)
                    dirnames.remove(p)
                elif root.find('./' + b) == 0:
                    logging.info("Pruning %s", a)
                    dirnames.remove(p)

        for _dir in dirnames:
            directories.put(os.path.relpath(os.path.join(root, _dir)))

        for _file in filenames:
            files.put(os.path.relpath(os.path.join(root, _file)))

    logging.warn("Done gathering local files")


def catalog_remote(app, objects):
    logging.warn("Grabbing remote objects")
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

    logging.warn("Objects %d", len(objects))


def upload_directory(app):
    """ Uploads an entire local directory. """
    manager = Manager()
    directories = manager.Queue()
    files = manager.Queue()
    remote_objects = manager.dict()
    uploads = manager.Queue()
    deletes = manager.Queue()

    harvest = list()
    harvest.append(Process(target=catalog_directory,
        args=(copy(app), app.source, files, directories,)))
    harvest.append(Process(target=catalog_remote,
        args=(copy(app), remote_objects,)))

    logging.info("Starting harvesters")
    for harvester in harvest:
        harvester.start()

    logging.info("Waiting for harvest")
    for harvester in harvest:
        harvester.join()

    del harvest

    # haven't needed to thread this out yet, but it's ready if it needs to
    logging.warn("Processing directories (%d)", directories.qsize())
    create_directories(app, directories, remote_objects)
    del directories

    pool = list()
    workers = list()

    # For each scanner, create an backlog manager as we don't want the http
    # backlog to grow too long and uploading/deleting will take 2-4x as long
    for p in xrange(app.threads):
        pool.append(Process(target=process_files,
           args=(copy(app), remote_objects, files, uploads)))
        if (p % 2) == 0:
            workers.append(Process(target=upload_files,
               args=(app.container, uploads)))
        else:
            workers.append(Process(target=delete_files,
               args=(app, deletes,)))

    logging.warn("Processing %d files (%d reads/%d writers)",
            files.qsize(), len(pool), len(workers))

    for s in (pool + workers):
        s.start()

    logging.info("Waiting for files to empty")
    # wait for the queue to empty
    while not files.empty():
        time.sleep(0.2)

    logging.info("Queue empty, joining readers")
    # join the readers after the queue in empty
    # as to not prematurely delete any files
    # that have pending operations
    for s in pool:
        s.join()

    # After the readers have all exited, we know that remote_objects
    # contains the remaining files that should be deleted from
    # the backups.  Dump these into a Queue for the writers to take
    # care of.
    logging.info("%d objects scheduled for deletion", len(remote_objects))
    for d in remote_objects.values():
        deletes.put((app.container, d))

    logging.info("Stopping uploaders")
    # tell the uploaders they are done
    for x in xrange(len(workers) / 2):
        uploads.put(None)
        deletes.put(None)

    # join the last of the threads
    logging.info("Joining writers")
    for s in workers:
        s.join()

    logging.warn("Done backing up %s to %s", app.source, app.container)


def encode_filename(string):
    string = str(string)
    uc = unicode(string, 'utf-8', 'replace')
    return uc.encode('ascii', 'replace')


def create_directories(app, directories, remote_objects):
    logging.info("Creating directories")
    container = get_container(app)
    while True:
        try:
            _dir = directories.get_nowait()
        except:
            break

        safe_dir = encode_filename(_dir)
        if safe_dir in remote_objects and \
            remote_objects[safe_dir].get('content_type', None) == \
           'application/directory':
            del remote_objects[safe_dir]
            continue

        logging.warn("Creating directory %s", safe_dir)

        obj = container.storage_object(safe_dir)
        obj.content_type = 'application/directory'
        obj.create()
        if safe_dir in remote_objects:
            del remote_objects[safe_dir]


def delete_files(app, objects):
    while True:
        try:
            _container, obj = objects.get()

            logging.info("Deleting %s", obj['name'])

            # Copy the file out of the way
            new_revision(app, _container,
                    obj['name'], obj.get('hash', 'deleted'))

            # then delete it as it no longer exists.
            rm = get_container(app, name=_container)\
                .storage_object(obj['name'])
            rm.delete()
        except:
            break


def process_files(app, objects, files, backlog):
    l = logging.getLogger('process_files')
    while True:
        try:
            _file = files.get_nowait()
        except:
            l.info("Queue empty, exiting file processor")
            break

        safe_filename = encode_filename(_file)

        # don't bother with checksums for new files
        if safe_filename not in objects:
            l.warn("Queued missing %s", safe_filename)
            backlog.put((_file, safe_filename,))
            continue

        oldhash = objects[safe_filename].get('hash', None)

        oldsize = int(objects[safe_filename].get('size'))
        cursize = int(get_filesize(_file))
        curdate = int(os.path.getmtime(_file))
        oldtime = objects[safe_filename].get('last_modified')

        # there are a few formats, try to figure out which one safely
        for timeformat in ['%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S']:
            try:
                oldtime = time.mktime(time.strptime(oldtime,
                    '%Y-%m-%dT%H:%M:%S.%f'))
            except ValueError:
                continue
            else:
                break

        if cursize == oldsize and oldtime >= curdate and not app.checkhash:
            l.debug("No change in filesize/date: %s", _file)
            del objects[safe_filename]
            continue
        elif app.checkhash:
            l.info("Checksumming %s", _file)
            newhash = swifthash(_file)

            if oldhash == newhash:
                l.debug("No change in checksum: %s", _file)
                del objects[safe_filename]
                continue
            else:
                l.info("Revised: HASH:%s:%s FILE:%s",
                        oldhash, newhash, safe_filename)
        else:
            l.info("Revised: SIZE:%s:%s DATE:%s:%s FILE:%s",
                    oldsize, cursize, oldtime, curdate, safe_filename)

        del objects[safe_filename]
        new_revision(app, _file, oldhash)
        backlog.put((_file, safe_filename,))


def new_revision(app, _from, marker):
    if app.retention < 1:
        logging.info("Retention disabled for %s", _from)
        return None

    # copy the file to the -revisions container so we don't
    # pollute the deleted items list.  Not putting revisions
    # in a seperate container will lead to an ever growing
    # list slowing down the backups

    _rev_container = app.container + "-revisions"

    safe_filename = encode_filename(_from)
    fs = os.path.splitext(safe_filename)
    new_file = fs[0] + "_" + marker + fs[1]

    container = get_container(app)
    revcontainer = get_container(app, name=_rev_container)
    revcontainer.create()

    obj = container.storage_object(safe_filename)
    rev = revcontainer.storage_object(new_file)

    if obj.exists():
        logging.warn("Copying %s to %s", obj.name, rev.name)

        rev.create()

        obj.copy_to(rev)
        delete_later(app, rev)


def delete_later(app, obj):
    """ lacking this in the bindings currently, work around it.
        Deletes a file after the specified number of days
    """
    delta = int(app.retention) * 24 * 60 * 60
    when = int(time.time()) + delta
    logging.info("Setting retention(%d) on %s", when, obj.name)

    headers = {
        'X-Delete-At': str(when),
        'Content-Length': '0'}
    obj.make_request('POST', headers=headers)


def upload_files(_container, jobs):
    container = get_container(app, name=_container)

    l = logging.getLogger('upload_files')
    while True:
        try:
            _file, target = jobs.get()
        except:
            logging.info("Uploader exiting")
            break

        try:
            obj = container.storage_object(target)
            obj.create()
            l.warn("Uploading file %s", obj.name)
            chunk_upload(obj, _file)
            l.warn("Finished file %s ", obj.name)
        except Exception, e:
            l.error("Failed to upload %s, requeueing. Error: %s", _file, e)
            jobs.put((_file, target,))
            # in case we got disconnected, reset the container
            container = get_container(app, name=_container)


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
    Yielded bytes might be less buflen.  Does not raise excepts for
    IOError"""
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
            "A contiainer will be created if it doesn't exist. "
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
