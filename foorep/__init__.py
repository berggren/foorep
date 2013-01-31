# Copyright (C) 2012 Johan Berggren.
# This file is part of foorep
# See the file 'LICENSE.txt' for copying permission.

import os
import sys
import imp
import glob
import uuid
import hashlib
import datetime

import pymongo
import gridfs

try:
    import magic
except ImportError:
    magic = None

class Repository:
    """Repository for forensic artifacts"""
    
    def __init__(self, host='127.0.0.1', port=27017, 
                 database='foorep', collection='repository'):
        """Creates a new or use an existing mongodb database and collection. 
        Sets up an instance of GridFS for storing files.

        :Parameters:
          - `host` mongoDB host
          - `port` mongoDB port
          - `database` mongoDB database
          - `collection` mongodb collection
        """
        try:
            self.db = pymongo.MongoClient(host=host, port=port)[database]
            self.collection = self.db[collection]
            self.fs = gridfs.GridFS(self.db)
        except pymongo.errors.ConnectionFailure:
            print("ERROR: Could not connect to collection %s on database %s" % (
                    database, 
                    collection))
            sys.exit()
        # find plugins
        plugin_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),"plugins")
        for path in glob.glob(os.path.join(plugin_dir,'[!_]*.py')): 
            name, ext = os.path.splitext(os.path.basename(path))
            imp.load_source(name, path)
        self.plugins = Plugin.get_plugins()
    
    def _create_document(self, fbuf=None, fpath=None, fname=None, gridfile=None):
        """Creates a dictionary based on the info of a file.

        :Parameters:
          - `fh` File-like object with read() function
        """
        stat = os.stat(fpath)
        if magic:
            try:
                filetype = magic.from_file(fpath)
            except AttributeError:
                filetype = 'N/A'
        else:
            filetype = 'N/A'

        document = {
            "uuid": uuid.uuid4().hex,
            "file": gridfile,
            "user": None,
            "meta": {
                "filename": fname,
                "filetype": filetype,
                "filesize": stat.st_size,
                "hash": {
                    "md5": hashlib.md5(fbuf).hexdigest(),
                    "sha1": hashlib.sha1(fbuf).hexdigest(),
                    "sha256": hashlib.sha256(fbuf).hexdigest(),
                    "sha512": hashlib.sha512(fbuf).hexdigest(),
                    "ssdeep": None
                    },
                },
            "annotations": {},
            "created": datetime.datetime.now(),
            "updated": datetime.datetime.now()
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
        document = self._create_document(fbuf=filebuffer, 
                fpath=filepath,
                fname=filename,
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
        new_annotation.append({"created": datetime.datetime.now(), "data": annotation.get('data')})
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

if __name__ == '__main__':
    pass
