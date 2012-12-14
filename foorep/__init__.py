# Copyright (C) 2012 Johan Berggren.
# This file is part of foorep
# See the file 'LICENSE.txt' for copying permission.

from pymongo import Connection
from pymongo import errors as mongoerr
from gridfs import GridFS
import os
import imp
import hashlib
from glob import glob
from uuid import uuid4
from datetime import datetime
import sys

try:
    import magic
except ImportError:
    magic = None

class PluginMount(type):
    def __init__(self, name, bases, attrs):
        if not hasattr(self, 'plugins'):
            self.plugins = []
        else:
            self.plugins.append(self)
    def get_plugins(self, *args, **kwargs):
        return [p(*args, **kwargs) for p in self.plugins]

class Plugin:
    __metaclass__ = PluginMount

class Repository:
    """Repository for malware samples."""
    
    def __init__(self, database='foorep', collection='repository'):
        """Creates a new or use an existing database and collection in
        MongoDB. Set up an instance of GridFS.

        :Parameters:
          - `database` (optional) Name of the MongoDB database
          - `collection` (optional) Name of the collection
        """
        try:
            self.db = Connection()[database]
            self.collection = self.db[collection]
            self.fs = GridFS(self.db)
        except mongoerr.ConnectionFailure:
            print "Connection ERROR, is mongoDB alive?"
            sys.exit()
        plugin_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),"plugins")
        for path in glob(os.path.join(plugin_dir,'[!_]*.py')): 
            name, ext = os.path.splitext(os.path.basename(path))
            imp.load_source(name, path)
        self.plugins = Plugin.get_plugins()
    def _create_document(self, file=None, filepath=None, filename=None, gridfile=None):
        """Creates a dictionary based on the info of a file.

        :Parameters:
          - `fh` File-like object with read() function
        """
        stat = os.stat(filepath)
        if magic:
            filetype = magic.from_file(filepath)
        else:
            filetype = 'No magic support'

        document = {
            "uuid": uuid4().hex,
            "file": gridfile,
            "user": None,
            "meta": {
                "filename": filename,
                "filetype": filetype,
                "filesize": stat.st_size,
                "hash": {
                    "md5": hashlib.md5(file).hexdigest(),
                    "sha1": hashlib.sha1(file).hexdigest(),
                    "sha256": hashlib.sha256(file).hexdigest(),
                    "sha512": hashlib.sha512(file).hexdigest(),
                    "ssdeep": None
                    },
                },
            "annotations": {},
            "created": datetime.now(),
            "updated": datetime.now()
            }
        return document

    def insert(self, fh, filename=None):
        """Insert information about file and the file itself to the repository.

        :Parameters:
          - `uri` Either a path to a local file or a URL to download
        """
        try:
            filebuffer = fh.read()
        except AttributeError:
            fh = open(fh, "rb")
            filebuffer = fh.read()
        filepath = fh.name
        if not filename:
            filename = os.path.basename(filepath)

        gridfile = self.fs.put(filebuffer,
                filename=filename)
        document = self._create_document(file=filebuffer, 
                filepath=filepath,
                filename=filename,
                gridfile=gridfile)
        self.collection.insert(document)
        for plugin in self.plugins:
            res = plugin.analyze(filepath)
            if res:
                self.annotate(document['uuid'], res)
        return document

    def remove(self, id):
        """Removes a document+file from the repository.

        :Parameters:
          - `id` MongoDB ObjectID or uuid
        """
        try:
            doc = self.get(id)
            file = doc.get('file')
        except:
            return None
        if file:
            if self.fs.exists(file):
                self.fs.delete(file)
        self.collection.remove(doc['_id'])
        return True 

    def annotate(self, id, annotation):
        """Add annotation to document.

        :Parameters:
          - `id` MongoDB ObjectID or uuid
          - `annotation` Dictionary with annotation
        """
        document = self.get(id)
        annotations = document.get('annotations')
        new_annotation = annotations.setdefault(annotation.get('type'), [])
        new_annotation.append({"created": datetime.now(), "value": annotation.get('value')})
        self.collection.save(document)
        return True

    def get(self, id):
        """Get document.

        :Parameters:
          - `id` MongoDB ObjectID or uuid
        """
        document = self.collection.find_one({'$or': [
            {"_id": id },
            {"uuid": id }
        ]})
        return document

    def get_file(self, id):
        """Get filehandler

        :Parameters:
          - `id` MongoDB (gridFS) ObjectID
        """
        return self.fs.get(id)

    def search(self, q):
        """Search for document.

        :Parameters:
          - `hash` md5, sha1, sha256 or sha512 to search for
        """
        result = []
        query = self.collection.find({'$or': [
            {"meta.hash.md5":       q},
            {"meta.hash.sha1":      q},
            {"meta.hash.sha256":    q},
            {"meta.hash.sha512":    q},
            {"uuid":                q},
            {"meta.filename":       {'$regex': q}}
        ]})
        for sample in query:
            result.append(sample)
        return result

    def list(self, limit=0):
        return self.collection.find().limit(limit)


