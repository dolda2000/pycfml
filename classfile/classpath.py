import os, zipfile
from . import file

class dir(object):
    def __init__(self, path):
        self.path = path

    def get(self, name):
        if '.' in name:
            raise FileNotFoundError(name)
        els = name.split('/')
        fn = os.path.join(self.path, *els[:-1], els[-1] + ".class")
        with open(fn, "rb") as fp:
            return file.classfile.load(fp)

class jar(object):
    def __init__(self, filename):
        self.filename = filename

    def get(self, name):
        with zipfile.ZipFile(self.filename) as jar:
            fn = name + ".class"
            try:
                fp = jar.open(fn, "r")
            except KeyError:
                raise FileNotFoundError(name)
            with fp:
                return file.classfile.load(fp)

class path(object):
    def __init__(self, *ents, caching=True):
        self.ents = ents
        self.cache = {} if caching else None

    def get(self, name):
        if self.cache is not None and name in self.cache:
            return self.cache[name]
        for ent in self.ents:
            try:
                ret = ent.get(name)
                break;
            except FileNotFoundError:
                pass
        else:
            raise FileNotFoundError(name)
        if self.cache is not None:
            self.cache[name] = ret
        return ret
