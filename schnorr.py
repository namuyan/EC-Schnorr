#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import ecc
import Crypto.Util.number
from binascii import hexlify, unhexlify
from hashlib import sha224

p = ecc.ECcurve().p
q = ecc.ECcurve().q
byte = ecc.ECcurve().fieldSize // 8
dataSize = 2**80


# --INT to bytes HEX
def _int2hex(i, b=byte):
    return hexlify(i.to_bytes(b, 'big')).decode('utf8')


# --bytes HEX to INT
def _hex2int(i):
    return int.from_bytes(unhexlify(i.encode('utf8')), 'big')


# --2element to hex
def _ele2hex(e):
    return _int2hex(e.x) + _int2hex(e.y)


# --hex to 2element
def _hex2ele(h):
    return _hex2int(h[:byte * 2]), _hex2int(h[byte * 2:])


# --get_private_key
def get_private_key():
    a = Crypto.Util.number.getRandomRange(0, (q - 1))
    return _int2hex(a)


# --get_public_key
def get_public_key(private_key):
    ec = ecc.ECcurve()
    pbp = ecc.ECPoint(ec.xi, ec.yi)
    pbp = pbp.multiplyPointByScalar(_hex2int(private_key))
    pbp = pbp.simmetric()
    return _ele2hex(pbp)


# --sign message
def sign(message, private_key):
    ec = ecc.ECcurve()
    r = Crypto.Util.number.getRandomRange(0, (q - 1))
    x = ecc.ECPoint(ec.xi, ec.yi)
    x = x.multiplyPointByScalar(r)

    # generates e
    # e = Crypto.Util.number.getRandomRange(0, 2**80)
    e = int.from_bytes(sha224(message).digest(), 'big') % dataSize
    """ calculate Y """
    y = _hex2int(private_key) * e + r

    return _ele2hex(x) + _int2hex(y, b=34)


def verify(message, x_y, public_key):
    px, py = _hex2ele(public_key)
    v = ecc.ECPoint(px, py)
    e = int.from_bytes(sha224(message).digest(), 'big') % dataSize
    print(hex(e))
    v = v.multiplyPointByScalar(e)

    # calculate z
    ec = ecc.ECcurve()
    z = ecc.ECPoint(ec.xi, ec.yi)
    z = z.multiplyPointByScalar(_hex2int(x_y[byte * 4:]))
    z = z.sum(v)

    # verify z e x
    xx, xy = _hex2ele(x_y[:byte * 4])
    if z.x == xx and z.y == xy:
        return True
    else:
        return False


if __name__ == "__main__":
    #pri = _int232hex(1742413906660797398263574261320583321084828220183690165741)
    #pub = _int232hex(241010344193812168014432711399629693373018093471884903517) + \
    #      _int232hex(2306444403712286640989713776754269629962048798612334189144)
    pri = get_private_key()
    pub = get_public_key(pri)
    print('pri', pri)
    print('pub', pub)
    import time

    t = time.time()
    for i in range(1000):
        message = b'hello my name is namuyan'
        xy = sign(message, pri)
        print("xy", xy)
        if not verify(message, xy, pub):
            exit(1)
    print((time.time() - t) / 60)
