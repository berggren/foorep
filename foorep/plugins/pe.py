# Copyright (C) 2012 Johan Berggren.
# This file is part of foorep
# See the file 'LICENSE.txt' for copying permission.

from datetime import datetime

from foorep import Plugin

class Pe(Plugin):
    def _overview(self, pe, pefile):
        return {
                "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
                "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "machine_type": pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine],
                "dll": pe.FILE_HEADER.IMAGE_FILE_DLL,
                "subsystem": pefile.SUBSYSTEM_TYPE[pe.OPTIONAL_HEADER.Subsystem],
                "timestamp": datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp),
                "number_of_rva_and_sizes": pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
            }

    def _imports(self, pe, pefile):
        ret = {}
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return None
        for lib in pe.DIRECTORY_ENTRY_IMPORT:
            l = []
            for imp in lib.imports:
                if (imp.name != None) and (imp.name != ""):
                    l.append(imp.name)
            ret[lib.dll.replace(".", "_")] = l
        return ret
        
    def analyze(self, path):
        try:
            import pefile
        except ImportError:
            return None
        try:
            pe = pefile.PE(path)
        except pefile.PEFormatError:
            return None
        result = {
            "type": "pe",
            "name": "PEfile",
            "annotation": {
                    "overview": self._overview(pe, pefile),
                    "imports": self._imports(pe, pefile)
                }
        }
        return result

