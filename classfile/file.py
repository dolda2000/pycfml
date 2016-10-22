import collections
from . import binfmt

ACC_PUBLIC       = 0x0001
ACC_PRIVATE      = 0x0002
ACC_PROTECTED    = 0x0004
ACC_STATIC       = 0x0008
ACC_FINAL        = 0x0010
ACC_SUPER        = 0x0020
ACC_SYNCHRONIZED = 0x0020
ACC_VOLATILE     = 0x0040
ACC_BRIDGE       = 0x0040
ACC_TRANSIENT    = 0x0080
ACC_VARARGS      = 0x0080
ACC_NATIVE       = 0x0100
ACC_INTERFACE    = 0x0200
ACC_ABSTRACT     = 0x0400
ACC_STRICT       = 0x0800
ACC_SYNTHETIC    = 0x1000
ACC_ANNOTATION   = 0x2000
ACC_ENUM         = 0x4000

CONSTANT_Class              = 7
CONSTANT_Fieldref           = 9
CONSTANT_Methodref          = 10
CONSTANT_InterfaceMethodref = 11
CONSTANT_String             = 8
CONSTANT_Integer            = 3
CONSTANT_Float              = 4
CONSTANT_Long               = 5
CONSTANT_Double             = 6
CONSTANT_NameAndType        = 12
CONSTANT_Utf8               = 1
CONSTANT_MethodHandle       = 15
CONSTANT_MethodType         = 16
CONSTANT_InvokeDynamic      = 18

version = collections.namedtuple("version", ["major", "minor"])
version.__eq__ = lambda s, o: s.major == o.major and s.minor == o.minor
version.__ne__ = lambda s, o: s.major != o.major or s.minor != o.minor
version.__lt__ = lambda s, o: (s.major < o.major) or (s.major == o.major and s.minor < o.minor)
version.__gt__ = lambda s, o: (s.major > o.major) or (s.major == o.major and s.minor > o.minor)
version.__le__ = lambda s, o: (s.major < o.major) or (s.major == o.major and s.minor <= o.minor)
version.__ge__ = lambda s, o: (s.major > o.major) or (s.major == o.major and s.minor >= o.minor)
version.J5 = version(49, 0)
version.J6 = version(50, 0)
version.J7 = version(51, 0)
version.J8 = version(52, 0)

class constint(object):
    def __init__(self, val):
        self.val = val
    def __hash__(self):
        return hash(constint) + self.val
    def __eq__(s, o):
        return isinstance(o, constint) and o.val == s.val
class constfloat(object):
    def __init__(self, val):
        self.val = val
    def __hash__(self):
        return hash(constfloat) + self.val
    def __eq__(s, o):
        return isinstance(o, constfloat) and o.val == s.val
class constlong(object):
    def __init__(self, val):
        self.val = val
    def __hash__(self):
        return hash(constlong) + self.val
    def __eq__(s, o):
        return isinstance(o, constlong) and o.val == s.val
class constdouble(object):
    def __init__(self, val):
        self.val = val
    def __hash__(self):
        return hash(constdouble) + self.val
    def __eq__(s, o):
        return isinstance(o, constdouble) and o.val == s.val

class conststr(object):
    def __init__(self, idx):
        self.idx = idx
    def __hash__(self):
        return hash(conststr) + self.idx
    def __eq__(s, o):
        return isinstance(o, conststr) and o.idx == s.idx

class classref(object):
    def __init__(self, nm):
        self.nm = nm
    def __hash__(self):
        return hash(classref) + self.nm
    def __eq__(s, o):
        return isinstance(o, classref) and o.nm == s.nm

class sig(object):
    def __init__(self, nm, tp):
        self.nm = nm
        self.tp = tp
    def __hash__(self):
        return hash(sig) + self.nm * 31 + self.tp
    def __eq__(s, o):
        return isinstance(o, sig) and o.nm == s.nm and o.tp == s.tp

class methodhandle(object):
    def __init__(self, kind, ref):
        self.kind = kind
        self.ref = ref
    def __hash__(self):
        return hash(methodhandle) + self.kind * 31 + self.ref
    def __eq__(s, o):
        return isinstance(o, methodhandle) and o.kind == s.kind and o.ref == s.ref

class methodtype(object):
    def __init__(self, desc):
        self.desc = desc
    def __hash__(self):
        return hash(methodhandle) + self.desc
    def __eq__(s, o):
        return isinstance(o, methodtype) and o.desc == s.desc

class callsite(object):
    def __init__(self, boot, sig):
        self.boot = boot
        self.sig = sig
    def __hash__(self):
        return hash(callsite) + self.boot * 31 + self.sig
    def __eq__(s, o):
        return isinstance(o, callsite) and o.boot == s.boot and o.sig == s.sig

class fieldref(object):
    def __init__(self, cls, sig):
        self.cls = cls
        self.sig = sig
    def __hash__(self):
        return hash(fieldref) + self.cls * 31 + self.sig
    def __eq__(s, o):
        return isinstance(o, fieldref) and o.cls == s.cls and o.sig == s.sig

class methodref(object):
    def __init__(self, cls, sig):
        self.cls = cls
        self.sig = sig
    def __hash__(self):
        return hash(methodref) + self.cls * 31 + self.sig
    def __eq__(s, o):
        return isinstance(o, methodref) and o.cls == s.cls and o.sig == s.sig

class imethodref(object):
    def __init__(self, cls, sig):
        self.cls = cls
        self.sig = sig
    def __hash__(self):
        return hash(imethodref) + self.cls * 31 + self.sig
    def __eq__(s, o):
        return isinstance(o, imethodref) and o.cls == s.cls and o.sig == s.sig

class field(object):
    def __init__(self, acc, nm, descr):
        self.acc = acc
        self.nm = nm
        self.descr = descr
        self.const = None
        self.syn = False
        self.sig = None
        self.deprecated = False
        self.rtann = []
        self.cpann = []
        self.attrs = []

class localdef(object):
    def __init__(self, start, end, nm, descr, reg):
        self.start = start
        self.end = end
        self.nm = nm
        self.descr = descr
        self.reg = reg

class code(object):
    def __init__(self):
        self.maxstack = 0
        self.maxlocals = 0
        self.code = b""
        self.exctab = []
        self.lintab = None
        self.locals = None
        self.tlocals = None
        self.attrs = []

class method(object):
    def __init__(self, acc, nm, descr):
        self.acc = acc
        self.nm = nm
        self.descr = descr
        self.code = None
        self.throws = []
        self.syn = False
        self.sig = None
        self.deprecated = False
        self.rtann = []
        self.cpann = []
        self.prtann = None
        self.pcpann = None
        self.anndef = None
        self.attrs = []

class annotation(object):
    def __init__(self, tp):
        self.tp = tp
        self.vals = {}

class innerclass(object):
    def __init__(self, cls, outer, nm, acc):
        self.cls = cls
        self.outer = outer
        self.nm = nm
        self.acc = acc

class classfile(object):
    MAGIC = 0xCAFEBABE

    def __init__(self, ver, access=None):
        self.ver = ver
        self.cp = []
        self.access = access
        self.this = None
        self.super = None
        self.ifaces = []
        self.fields = []
        self.methods = []
        self.srcfile = None
        self.innerclasses = []
        self.enclosingmethod = None
        self.syn = False
        self.sig = None
        self.deprecated = False
        self.rtann = []
        self.cpann = []
        self.attrs = []

    def loadconstant(self, buf):
        t = buf.uint8()
        if t == CONSTANT_Utf8:
            return binfmt.mutf8dec(buf.splice(buf.uint16())), False
        elif t == CONSTANT_Class:
            return classref(buf.uint16()), False
        elif t == CONSTANT_String:
            return conststr(buf.uint16()), False
        elif t == CONSTANT_Integer:
            return constint(buf.int32()), False
        elif t == CONSTANT_Float:
            return constfloat(buf.float32()), False
        elif t == CONSTANT_Long:
            return constlong(buf.int64()), True
        elif t == CONSTANT_Double:
            return constdouble(buf.float64()), True
        elif t == CONSTANT_Fieldref:
            return fieldref(buf.uint16(), buf.uint16()), False
        elif t == CONSTANT_Methodref:
            return methodref(buf.uint16(), buf.uint16()), False
        elif t == CONSTANT_InterfaceMethodref:
            return imethodref(buf.uint16(), buf.uint16()), False
        elif t == CONSTANT_NameAndType:
            return sig(buf.uint16(), buf.uint16()), False
        elif t == CONSTANT_MethodHandle:
            return methodhandle(buf.uint8(), buf.uint16()), False
        elif t == CONSTANT_MethodType:
            return methodtype(buf.uint16()), False
        elif t == CONSTANT_InvokeDynamic:
            return callsite(buf.uint16(), buf.uint16()), False
        else:
            raise binfmt.fmterror("unknown constant tag: " + str(t))

    def saveconstant(self, buf, const):
        if isinstance(const, str):
            enc = binfmt.mutf8enc(const)
            buf.uint8(CONSTANT_Utf8).uint16(len(enc)).extend(enc)
        elif isinstance(const, classref):
            buf.uint8(CONSTANT_Class).uint16(const.nm)
        elif isinstance(const, conststr):
            buf.uint8(CONSTANT_String).uint16(const.idx)
        elif isinstance(const, constint):
            buf.uint8(CONSTANT_Integer).int32(const.val)
        elif isinstance(const, constfloat):
            buf.uint8(CONSTANT_Float).float32(const.val)
        elif isinstance(const, constlong):
            buf.uint8(CONSTANT_Long).int64(const.val)
        elif isinstance(const, constdouble):
            buf.uint8(CONSTANT_Double).float64(const.val)
        elif isinstance(const, fieldref):
            buf.uint8(CONSTANT_Fieldref).uint16(const.cls).uint16(const.sig)
        elif isinstance(const, methodref):
            buf.uint8(CONSTANT_Methodref).uint16(const.cls).uint16(const.sig)
        elif isinstance(const, imethodref):
            buf.uint8(CONSTANT_InterfaceMethodref).uint16(const.cls).uint16(const.sig)
        elif isinstance(const, sig):
            buf.uint8(CONSTANT_NameAndType).uint16(const.nm).uint16(const.tp)
        elif isinstance(const, methodhandle):
            buf.uint8(CONSTANT_MethodHandle).uint8(const.kind).uint16(const.ref)
        elif isinstance(const, methodtype):
            buf.uint8(CONSTANT_MethodType).uint16(const.desc)
        elif isinstance(const, callsite):
            buf.uint8(CONSTANT_InvokeDynamic).uint16(const.boot).uint16(const.sig)
        else:
            raise Exception("unexpected object type in constant pool: " + const)

    def checkcp(self, idx, tp):
        return 0 <= idx < len(self.cp) and isinstance(self.cp[idx], tp)

    def intern(self, const, new=Exception):
        for i, cur in enumerate(self.cp):
            if cur == const:
                return i
        if new == Exception:
            raise Exception("constant not present in pool: " + const)
        if new:
            self.cp.append(const)
            return len(self.cp) - 1
        else:
            return None

    def loadattr(self, buf):
        nm = buf.uint16()
        if not self.checkcp(nm, str):
            raise binfmt.fmterror("invalid attribute name reference")
        return nm, binfmt.decbuf(buf.splice(buf.uint32()))

    def saveattrs(self, buf, attrs):
        buf.uint16(len(attrs))
        for nm, data in attrs:
            buf.uint16(nm).uint32(len(data)).extend(data)

    def loadannval(self, buf):
        t = chr(buf.uint8())
        if t in "BCDFIJSZs":
            return buf.uint16()
        elif t == "e":
            return (buf.uint16(), buf.uint16())
        elif t == "c":
            return classref(buf.uint16()) # XXX, but meh
        elif t == "@":
            return loadannotation(buf)
        elif t == "[":
            return [self.loadannval(buf) for i in range(buf.uint16())]
        else:
            raise binfmt.fmterror("unknown annotation-value type tag: " + t)

    def saveannval(self, buf, val):
        if isinstance(val, int):
            const = self.cp[val]
            if isinstance(const, str):
                buf.uint8(ord('s')).uint16(val)
            else:
                raise Exception("unexpected constant type in annotation value: " + const)
        elif isinstance(val, tuple) and len(val) == 2:
            buf.uint8(ord('e')).uint16(val[0]).uint16(val[1])
        elif isinstance(val, classref):
            buf.uint8(ord('c')).uint16(val.nm)
        elif isinstance(val, annotation):
            buf.uint8(ord('@'))
            saveannotation(buf, val)
        elif isinstance(val, list):
            buf.uint8(ord('['))
            for sval in val: self.saveannval(buf, sval)
        else:
            raise Exception("unexpected annotation value type: " + val)

    def loadannotation(self, buf):
        tp = buf.uint16()
        if not self.checkcp(tp, str):
            raise binfmt.fmterror("invalid annotation type reference")
        ret = annotation(tp)
        nval = buf.uint16()
        for i in range(nval):
            nm = buf.uint16()
            if not self.checkcp(nm, str):
                raise binfmt.fmterror("invalid annotation-value name reference")
            ret.vals[nm] = self.loadannval(buf)
        return ret

    def saveannotation(self, buf, ann):
        buf.uint16(ann.tp)
        buf.uint16(len(ann.vals))
        for key, val in ann.vals.items():
            buf.uint16(key)
            self.saveannval(buf, val)

    def loadfield(self, buf):
        acc = buf.uint16()
        nm = buf.uint16()
        if not self.checkcp(nm, str):
            raise binfmt.fmterror("invalid field name reference")
        descr = buf.uint16()
        if not self.checkcp(descr, str):
            raise binfmt.fmterror("invalid field descriptor reference")
        ret = field(acc, nm, descr)
        nattr = buf.uint16()
        for i in range(nattr):
            nm, data = self.loadattr(buf)
            pnm = self.cp[nm]
            if pnm == "ConstantValue":
                ret.const = data.uint16()
            elif pnm == "Synthetic":
                ret.syn = True
            elif pnm == "Signature":
                ret.sig = data.uint16()
            elif pnm == "Deprecated":
                ret.deprecated = True
            elif pnm == "RuntimeVisibleAnnotations":
                for o in range(data.uint16()):
                    ret.rtann.append(self.loadannotation(data))
            elif pnm == "RuntimeInvisibleAnnotations":
                for o in range(data.uint16()):
                    ret.cpann.append(self.loadannotation(data))
            else:
                ret.attrs.append((nm, data.splice()))
        return ret

    def savefield(self, buf, field):
        buf.uint16(field.acc)
        buf.uint16(field.nm).uint16(field.descr)
        attrs = list(field.attrs)
        enc = binfmt.encbuf
        if field.const is not None:
            attrs.append((self.intern("ConstantValue"), enc().uint16(field.const)))
        if field.syn:
            attrs.append((self.intern("Synthetic"), b""))
        if field.sig is not None:
            attrs.append((self.intern("Signature"), enc().uint16(field.sig)))
        if field.deprecated:
            attrs.append((self.intern("Deprecated"), b""))
        if len(field.rtann) > 0:
            data = enc()
            data.uint16(len(field.rtann))
            for ann in field.rtann: self.saveannotation(data, ann)
            attrs.append((self.intern("RuntimeVisibleAnnotations"), data))
        if len(field.cpann) > 0:
            data = enc()
            data.uint16(len(field.cpann))
            for ann in field.cpann: self.saveannotation(data, ann)
            attrs.append((self.intern("RuntimeInvisibleAnnotations"), data))
        self.saveattrs(buf, attrs)

    def loadcode(self, buf):
        ret = code()
        ret.maxstack = buf.uint16()
        ret.maxlocals = buf.uint16()
        ret.code = buf.splice(buf.uint32())
        for i in range(buf.uint16()):
            estart = buf.uint16()
            eend = buf.uint16()
            ehnd = buf.uint16()
            ctp = buf.uint16()
            if not (ctp == 0 or self.checkcp(ctp, classref)):
                raise binfmt.fmterror("invalid exception-catch reference")
            ret.exctab.append((estart, eend, ehnd, ctp))
        nattr = buf.uint16()
        for i in range(nattr):
            nm, data = self.loadattr(buf)
            pnm = self.cp[nm]
            if pnm == "LineNumberTable":
                lintab = []
                for o in range(data.uint16()):
                    pc = data.uint16()
                    ln = data.uint16()
                    lintab.append((pc, ln))
                ret.lintab = lintab
            elif pnm in ("LocalVariableTable", "LocalVariableTypeTable"):
                locals = []
                for o in range(data.uint16()):
                    start = data.uint16()
                    ln = data.uint16()
                    nm = data.uint16()
                    descr = data.uint16()
                    reg = data.uint16()
                    if not self.checkcp(nm, str):
                        raise binfmt.fmterror("invalid local variable name reference")
                    if not self.checkcp(descr, str):
                        raise binfmt.fmterror("invalid local variable descriptor reference")
                    locals.append(localdef(start, start + ln, nm, descr, reg))
                if nm == "LocalVariableTypeTable":
                    ret.tlocals = locals
                else:
                    ret.locals = locals
            else:
                ret.attrs.append((nm, data.splice()))
        return ret

    def savecode(self, buf, code):
        buf.uint16(code.maxstack).uint16(code.maxlocals)
        buf.uint32(len(code.code)).extend(code.code)
        buf.uint16(len(code.exctab))
        for estart, eend, ehnd, ctp in code.exctab:
            buf.uint16(estart).uint16(eend).uint16(ehnd).uint16(ctp)
        attrs = list(code.attrs)
        enc = binfmt.encbuf
        if code.lintab is not None:
            data = enc()
            data.uint16(len(code.lintab))
            for pc, ln in code.lintab:
                data.uint16(pc).uint16(ln)
            attrs.append((self.intern("LineNumberTable"), data))
        def savelocals(ltab):
            data = enc()
            data.uint16(len(ltab))
            for local in ltab:
                data.uint16(local.start).uint16(local.end - local.start).uint16(local.nm).uint16(local.descr).uint16(local.reg)
            return data
        if code.locals is not None:
            attrs.append((self.intern("LocalVariableTable"), savelocals(code.locals)))
        if code.tlocals is not None:
            attrs.append((self.intern("LocalVariableTypeTable"), savelocals(code.tlocals)))
        self.saveattrs(buf, attrs)

    def loadmethod(self, buf):
        acc = buf.uint16()
        nm = buf.uint16()
        if not self.checkcp(nm, str):
            raise binfmt.fmterror("invalid field name reference")
        descr = buf.uint16()
        if not self.checkcp(descr, str):
            raise binfmt.fmterror("invalid field descriptor reference")
        ret = method(acc, nm, descr)
        nattr = buf.uint16()
        for i in range(nattr):
            nm, data = self.loadattr(buf)
            pnm = self.cp[nm]
            if pnm == "Code":
                ret.code = self.loadcode(data)
            elif pnm == "Exceptions":
                for o in range(data.uint16()):
                    eref = data.uint16()
                    if not self.checkcp(eref, classref):
                        raise binfmt.fmterror("invalid exception reference")
                    ret.throws.append(eref)
            elif pnm == "Synthetic":
                ret.syn = True
            elif pnm == "Signature":
                ret.sig = data.uint16()
            elif pnm == "Deprecated":
                ret.deprecated = True
            elif pnm == "RuntimeVisibleAnnotations":
                for o in range(data.uint16()):
                    ret.rtann.append(self.loadannotation(data))
            elif pnm == "RuntimeInvisibleAnnotations":
                for o in range(data.uint16()):
                    ret.cpann.append(self.loadannotation(data))
            elif pnm == "RuntimeVisibleParameterAnnotations":
                ret.prtann = []
                for o in range(data.uint8()):
                    abuf = []
                    for u in range(data.uint16()):
                        abuf.append(self.loadannotation(data))
                    ret.prtann.append(abuf)
            elif pnm == "RuntimeInvisibleParameterAnnotations":
                ret.pcpann = []
                for o in range(data.uint8()):
                    abuf = []
                    for u in range(data.uint16()):
                        abuf.append(self.loadannotation(data))
                    ret.pcpann.append(abuf)
            elif pnm == "AnnotationDefault":
                ret.anndef = self.loadannval(data)
            else:
                ret.attrs.append((nm, data.splice()))
        return ret

    def savemethod(self, buf, method):
        buf.uint16(method.acc)
        buf.uint16(method.nm).uint16(method.descr)
        attrs = list(method.attrs)
        enc = binfmt.encbuf
        if method.code:
            data = enc()
            self.savecode(data, method.code)
            attrs.append((self.intern("Code"), data))
        if len(method.throws) > 0:
            data = enc()
            data.uint16(len(method.throws))
            for eref in method.throws: data.uint16(eref)
            attrs.append((self.intern("Exceptions"), data))
        if method.syn:
            attrs.append((self.intern("Synthetic"), b""))
        if method.sig is not None:
            attrs.append((self.intern("Signature"), enc().uint16(method.sig)))
        if method.deprecated:
            attrs.append((self.intern("Deprecated"), b""))
        if len(method.rtann) > 0:
            data = enc()
            data.uint16(len(method.rtann))
            for ann in method.rtann: self.saveannotation(data, ann)
            attrs.append((self.intern("RuntimeVisibleAnnotations"), data))
        if len(method.cpann) > 0:
            data = enc()
            data.uint16(len(method.cpann))
            for ann in method.cpann: self.saveannotation(data, ann)
            attrs.append((self.intern("RuntimeInvisibleAnnotations"), data))
        if method.prtann is not None:
            data = enc()
            data.uint8(len(method.prtann))
            for par in method.prtann:
                buf.uint16(len(par))
                for ann in par: self.saveannotation(data, ann)
            attrs.append((self.intern("RuntimeVisibleParameterAnnotations"), data))
        if method.pcpann is not None:
            data = enc()
            data.uint8(len(method.pcpann))
            for par in method.pcpann:
                buf.uint16(len(par))
                for ann in par: self.saveannotation(data, ann)
            attrs.append((self.intern("RuntimeInvisibleParameterAnnotations"), data))
        if method.anndef is not None:
            data = enc()
            self.saveannval(data, method.anndef)
            attrs.append((self.intern("AnnotationDefault"), data))
        self.saveattrs(buf, attrs)

    @classmethod
    def load(cls, fp):
        buf = binfmt.decstream(fp)
        if buf.uint32() != cls.MAGIC:
            raise binfmt.fmterror("invalid magic number")
        minor, major = buf.uint16(), buf.uint16()
        self = cls(version(major, minor))

        cplen = buf.uint16()
        if cplen < 1:
            raise binfmt.fmterror("invalid constant-pool length")
        self.cp.append(None)
        while len(self.cp) < cplen:
            loaded, dbl = self.loadconstant(buf)
            self.cp.append(loaded)
            if dbl:
                self.cp.append(None)

        self.acc = buf.uint16()
        self.this = buf.uint16()
        self.super = buf.uint16()
        if not self.checkcp(self.this, classref):
            raise binfmt.fmterror("invalid class name reference")
        if not self.checkcp(self.super, classref):
            raise binfmt.fmterror("invalid super-class reference")
        iflen = buf.uint16()
        while len(self.ifaces) < iflen:
            iref = buf.uint16()
            if not self.checkcp(iref, classref):
                raise binfmt.fmterror("invalid interface reference")
            self.ifaces.append(iref)

        nfields = buf.uint16()
        while len(self.fields) < nfields:
            self.fields.append(self.loadfield(buf))
        nmethods = buf.uint16()
        while len(self.methods) < nmethods:
            self.methods.append(self.loadmethod(buf))

        nattrs = buf.uint16()
        for i in range(nattrs):
            nm, data = self.loadattr(buf)
            pnm = self.cp[nm]
            if pnm == "SourceFile":
                self.srcfile = data.uint16()
            elif pnm == "Signature":
                self.sig = data.uint16()
            elif pnm == "Synthetic":
                self.syn = True
            elif pnm == "Deprecated":
                self.deprecated = True
            elif pnm == "InnerClasses":
                for o in range(data.uint16()):
                    cref = data.uint16()
                    outer = data.uint16()
                    cnm = data.uint16()
                    acc = data.uint16()
                    if not self.checkcp(cref, classref):
                        raise binfmt.fmterror("invalid inner-class reference")
                    if not (outer == 0 or self.checkcp(outer, classref)):
                        raise binfmt.fmterror("invalid inner-class outer reference")
                    if not (cnm == 0 or self.checkcp(cnm, str)):
                        raise binfmt.fmterror("invalid inner-class name reference")
                    self.innerclasses.append(innerclass(cref, outer, cnm, acc))
            elif pnm == "EnclosingMethod":
                self.enclosingmethod = (data.uint16(), data.uint16())
                if not self.checkcp(self.enclosingmethod[0], classref):
                    raise binfmt.fmterror("invalid enclosing-method class reference")
                if not (self.enclosingmethod[1] == 0 or self.checkcp(self.enclosingmethod[1], sig)):
                    raise binfmt.fmterror("invalid enclosing-method method reference")
            elif pnm == "RuntimeVisibleAnnotations":
                for o in range(data.uint16()):
                    self.rtann.append(self.loadannotation(data))
            elif pnm == "RuntimeInvisibleAnnotations":
                for o in range(data.uint16()):
                    self.cpann.append(self.loadannotation(data))
            else:
                self.attrs.append((nm, data.splice()))

        return self

    def _save(self, buf):
        buf.uint32(self.MAGIC)
        buf.uint16(self.ver.minor).uint16(self.ver.major)

        buf.uint16(len(self.cp))
        for const in self.cp:
            if const is not None:
                self.saveconstant(buf, const)

        buf.uint16(self.acc)
        buf.uint16(self.this).uint16(self.super)
        buf.uint16(len(self.ifaces))
        for iref in self.ifaces: buf.uint16(iref)

        buf.uint16(len(self.fields))
        for field in self.fields:
            self.savefield(buf, field)

        buf.uint16(len(self.methods))
        for method in self.methods:
            self.savemethod(buf, method)

        enc = binfmt.encbuf
        attrs = list(self.attrs)
        if self.srcfile is not None:
            attrs.append((self.intern("SourceFile"), enc().uint16(self.srcfile)))
        if self.syn:
            attrs.append((self.intern("Synthetic"), b""))
        if self.deprecated:
            attrs.append((self.intern("Deprecated"), b""))
        if self.sig is not None:
            attrs.append((self.intern("Signature"), enc().uint16(self.sig)))
        if len(self.innerclasses) > 0:
            data = enc()
            data.uint16(len(self.innerclasses))
            for inner in self.innerclasses: data.uint16(inner.cls).uint16(inner.outer).uint16(inner.nm).uint16(inner.acc)
            attrs.append((self.intern("InnerClasses"), data))
        if self.enclosingmethod is not None:
            attrs.append((self.intern("EnclosingMethod"), enc().uint16(self.enclosingmethod[0]).uint16(self.enclosingmethod[1])))
        if len(self.rtann) > 0:
            data = enc()
            data.uint16(len(self.rtann))
            for ann in self.rtann: self.saveannotation(data, ann)
            attrs.append((self.intern("RuntimeVisibleAnnotations"), data))
        if len(self.cpann) > 0:
            data = enc()
            data.uint16(len(self.cpann))
            for ann in self.cpann: self.saveannotation(data, ann)
            attrs.append((self.intern("RuntimeInvisibleAnnotations"), data))
        self.saveattrs(buf, attrs)

    def save(self, fp):
        return self._save(binfmt.encstream(fp))

    @classmethod
    def fromfile(cls, fn):
        with open(fn, "rb") as fp:
            return cls.load(fp)

    def tofile(self, fn):
        with open(fn, "wb") as fp:
            return self.save(fp)
