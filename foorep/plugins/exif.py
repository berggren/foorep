# Copyright (C) 2012 Johan Berggren.
# This file is part of foorep
# See the file 'LICENSE.txt' for copying permission.

from foorep import Plugin

class Exif(Plugin):
    def analyze(self, path):
        try:
            import pyexiv2
        except ImportError:
            return None
        try:
            exif = pyexiv2.ImageMetadata(path)
            exif.read()
        except IOError:
            return None
        self.tags = exif.exif_keys
        result = {
            "type": "exif",
            "name": "EXIF",
            "annotation": {},
        }
        if self.tags:
            for tag in exif.exif_keys:
                result['annotation'][tag.replace(".", "_")] = exif[tag].human_value
        return result 
