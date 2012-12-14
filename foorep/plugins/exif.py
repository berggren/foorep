# Copyright (C) 2012 Johan Berggren.
# This file is part of foorep
# See the file 'LICENSE.txt' for copying permission.

from foorep import Plugin

class Exif(Plugin):
    def analyze(self, path):
        try:
            import pyexiv2
        except ImportError:
            return
        try:
            exif = pyexiv2.ImageMetadata(path)
            exif.read()
            self.tags = exif.exif_keys
        except IOError:
            return None
        if self.tags:
            result = {
                    "type": "exif",
                    "value": {},
            }
            for tag in exif.exif_keys:
                result['value'][tag.replace(".", "_")] = exif[tag].human_value
        else:
            result = None
        return result 
