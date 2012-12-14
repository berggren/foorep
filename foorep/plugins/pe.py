# Copyright (C) 2012 Johan Berggren.
# This file is part of foorep
# See the file 'LICENSE.txt' for copying permission.

from foorep import Plugin
from datetime import datetime

class Pe(Plugin):
    def analyze(self, path):
        try:
            import pefile
        except ImportError:
            return
        try:
            pe = pefile.PE(path)
        except pefile.PEFormatError:
            return None
        result = {
            "type": "pefile",
            "value": {
                "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
                "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "machine_type": pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine],
                "dll": pe.FILE_HEADER.IMAGE_FILE_DLL,
                "subsystem": pefile.SUBSYSTEM_TYPE[pe.OPTIONAL_HEADER.Subsystem],
                "timestamp": datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp),
                "number_of_rva_and_sizes": pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
            }
        }
        return result
