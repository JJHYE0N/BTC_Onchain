import codecs
from hashlib import *
from base58 import *
from hashlib import sha256


def scriptsig_to_addr(tmpHex):
    #pubkey = tmpHex[146:]
    pubkey = bytearray.fromhex(tmpHex[146:])
    round1 = sha256(pubkey).digest()
    h = new('ripemd160')
    h.update(round1)
    pubkey_hash = h.digest()
    data = b'\x00' + pubkey_hash
    shaencode = sha256(sha256(data).digest()).digest()
    res = b58encode(data + shaencode[:4])
    result = res.decode('utf-8')
    return result

tmpHex = "473044022017e2af6e1308d431365deeb5739d41a909cf0d61a9c0e48f3ae5b0bd6544bfc5022066e73dd26d71d824552b034b322603cce8b936912b99f4f3df512e502bd7c11e012103d7b3bc2d0b4b72a845c469c9fee3c8cf475a2f237e379d7f75a4f463f7bd6ebd"
print(scriptsig_to_addr(tmpHex))
