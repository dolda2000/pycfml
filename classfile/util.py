def resource(cls, newfile, lnoff):
    cls.srcfile = cls.intern(newfile, True)
    for method in cls.methods:
        if method.code and method.code.lintab:
            method.code.lintab = [(pc, lin + lnoff) for pc, lin in method.code.lintab]
