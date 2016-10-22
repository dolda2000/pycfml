from struct import pack, unpack, calcsize

class fmterror(Exception):
    pass

class eomerror(fmterror):
    pass

def mutf8dec(bs):
    ret = ""
    i = 0
    while i < len(bs):
        b = bs[i]
        i += 1
        if b & 0x80 == 0:
            ret += chr(b)
        else:
            c = 0
            while (c < 7) and (b & (1 << (6 - c))):
                c += 1
            if c == 0 or c == 7: raise fmterror("invalid utf8 start-byte")
            iacc = acc = b & ((1 << (6 - c)) - 1)
            ic = c
            while c > 0:
                if i >= len(bs): raise fmterror("unterminated utf8 compound")
                b = bs[i]
                i += 1
                if b & 0xc0 != 0x80: raise fmterror("invalid utf8 continuation byte")
                acc = (acc << 6) | b & 0x3f
                c -= 1
            if iacc == 0 and ic != 2 and acc != 0: raise fmterror("invalid utf8 compound")
            ret += chr(acc)
    return ret

def mutf8enc(cs):
    ret = bytearray()
    for c in cs:
        c = ord(c)
        if c == 0:
            ret.extend(b"\xc0\x80")
        elif 1 <= c < 128:
            ret.append(c)
        elif 128 <= c < 2048:
            ret.append(0xc0 | ((c & 0x7c0) >> 6))
            ret.append(0x80 |  (c & 0x03f))
        elif 2048 <= c < 65536:
            ret.append(0xe0 | ((c & 0xf000) >> 12))
            ret.append(0x80 | ((c & 0x0fc0) >> 6))
            ret.append(0x80 |  (c & 0x003f))
        else:
            raise fmterror("non-BMP unicode not supported by Java")
    return bytes(ret)

class decoder(object):
    def destruct(self, fmt):
        return unpack(fmt, self.splice(calcsize(fmt)))

    def skip(self, ln):
        self.splice(ln)

    def int8(self):
        return self.destruct(">b")[0]
    def uint8(self):
        return self.destruct(">B")[0]
    def int16(self):
        return self.destruct(">h")[0]
    def uint16(self):
        return self.destruct(">H")[0]
    def int32(self):
        return self.destruct(">i")[0]
    def uint32(self):
        return self.destruct(">I")[0]
    def int64(self):
        return self.destruct(">q")[0]
    def uint64(self):
        return self.destruct(">Q")[0]
    def float32(self):
        return self.destruct(">f")[0]
    def float64(self):
        return self.destruct(">d")[0]

class decstream(decoder):
    def __init__(self, bk):
        self.bk = bk
        self.buf = bytearray()

    def eom(self):
        if len(self.buf) > 0:
            return False
        ret = self.bk.read(1024)
        if ret == b"":
            return True
        self.buf.extend(ret)
        return False

    def tell(self):
        return self.bk.tell() - len(self.buf)

    def splice(self, ln=-1):
        buf = self.buf
        if ln < 0:
            while True:
                ret = self.bk.read()
                if ret == b"":
                    self.buf = bytearray()
                    return bytes(buf)
                buf.extend(ret)
        else:
            while len(buf) < ln:
                rl = max(ln - len(buf), 1024)
                ret = self.bk.read(rl)
                if ret == b"":
                    raise eomerror("unexpected end-of-file")
                buf.extend(ret)
            self.buf = buf[ln:]
            return bytes(buf[:ln])

    def skip(self, ln):
        if ln < len(self.buf):
            self.buf = self.buf[ln:]
        else:
            ln -= len(self.buf)
            self.buf = bytearray()
            if hasattr(self.bk, "seek"):
                self.bk.seek(ln - 1, 1)
                if len(self.bk.read(1)) != 1:
                    raise eomerror("unexpected end-of-file")
            else:
                while ln > 0:
                    r = self.bk.read(ln)
                    if r == b"":
                        raise eomerror("unexpected end-of-file")
                    ln -= len(r)

    def str(self):
        buf = self.buf
        p = 0
        while True:
            p2 = buf.find(b'\0', p)
            if p2 > 0:
                self.buf = buf[p2 + 1:]
                return str(buf[:p2], "utf-8")
            ret = self.bk.read(1024)
            if ret == b"":
                if len(buf) == 0:
                    raise eomerror("unexpected end-of-file")
                raise fmterror("no string terminator found")
            p = len(buf)
            buf.extend(ret)

    def close(self):
        self.bk.close()

    def __enter__(self):
        return self

    def __exit__(self, *excinfo):
        self.close()
        return False

class decbuf(decoder):
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def __len__(self):
        return len(self.data) - self.offset

    def eom(self):
        return self.offset >= len(self.data)

    def splice(self, ln=-1):
        if ln < 0:
            ret = self.data[self.offset:]
            self.offset = len(self.data)
            return ret
        else:
            if self.offset + ln > len(self.data):
                raise eomerror("out of data to decode")
            ret = self.data[self.offset:self.offset + ln]
            self.offset += ln
            return ret

    def str(self):
        p = self.data.find(b'\0', self.offset)
        if p < 0:
            if self.offset == len(self.data):
                raise eomerror("out of data to decode")
            raise fmterror("no string terminator found")
        ret = str(self.data[self.offset:p], "utf-8")
        self.offset = p + 1
        return str(ret)

class encoder(object):
    def enstruct(self, fmt, *args):
        self.extend(pack(fmt, *args))
        return self

    def int8(self, val):
        self.enstruct(">b", val)
        return self
    def uint8(self, val):
        self.enstruct(">B", val)
        return self
    def int16(self, val):
        self.enstruct(">h", val)
        return self
    def uint16(self, val):
        self.enstruct(">H", val)
        return self
    def int32(self, val):
        self.enstruct(">i", val)
        return self
    def uint32(self, val):
        self.enstruct(">I", val)
        return self
    def int64(self, val):
        self.enstruct(">q", val)
        return self
    def uint64(self, val):
        self.enstruct(">Q", val)
        return self
    def float32(self, val):
        self.enstruct(">f", val)
        return self
    def float64(self, val):
        self.enstruct(">d", val)
        return self

    def str(self, val):
        if val.find('\0') >= 0:
            raise ValueError("encoded strings must not contain NULs")
        self.extend(val.encode("utf-8"))
        self.extend(b"\0")
        return self

    def ttol(self, val, term=False):
        for obj in val:
            if isinstance(obj, int):
                if 0 <= obj < 256:
                    self.uint8(T_UINT8)
                    self.uint8(obj)
                elif 0 <= obj < 65536:
                    self.uint8(T_UINT16)
                    self.uint16(obj)
                else:
                    self.uint8(T_INT)
                    self.int32(obj)
            elif isinstance(obj, str):
                self.uint8(T_STR)
                self.str(obj)
            elif isinstance(obj, utils.coord):
                self.uint8(T_COORD)
                self.coord(obj)
            elif isinstance(obj, utils.color):
                self.uint8(T_COLOR)
                self.color(obj)
            elif isinstance(obj, list):
                self.uint8(T_TTOL)
                self.ttol(obj, True)
            elif isinstance(obj, float):
                self.uint8(T_FLOAT32)
                self.float32(obj)
            elif obj is None:
                self.uint8(T_NIL)
            elif isinstance(obj, collections.ByteString):
                self.uint8(T_BYTES)
                if len(obj) < 128:
                    self.uint8(len(obj))
                else:
                    self.uint8(0x80).int32(len(obj))
                self.extend(obj)
            else:
                raise ValueError("unexpected type in tto-list: %s" % type(obj))
        if term:
            self.uint8(T_END)
        return self

class encstream(encoder):
    def __init__(self, bk):
        self.bk = bk

    def extend(self, data):
        self.bk.write(data)
        return self

    def close(self):
        self.bk.close()

    def __enter__(self):
        return self

    def __exit__(self, *excinfo):
        self.close()
        return False

class encbuf(encoder, bytearray):
    def extend(self, data):
        bytearray.extend(self, data)
        return self
