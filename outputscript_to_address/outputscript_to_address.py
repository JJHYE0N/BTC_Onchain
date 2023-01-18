import base58
import codecs
import hashlib
from hashlib import sha256


def scriptpubkey_to_addr(tmpHex):
    # 01 : output script to pubkey
    # print('Output Script: ',pubkey)
    
    pubkey = tmpHex[2:-2]

    # 02 : pubkey to SHA256 hashing
    # hash = sha256(bytes.fromhex(‘0496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858ee’))
    #pubkey_list = []
    # hash = sha256(bytes.fromhex(pubkey_list))
    
    #hash = sha256(bytes.fromhex('03564213318d739994e4d9785bf40eac4edbfa21f0546040ce7e6859778dfce5d4'))
    hash = sha256(bytes.fromhex(pubkey))
    hx = hash.hexdigest()
    # print('SHA256(Hex): ', hx)

    # 03 : SHA256 value to RIPEMD160
    hx = codecs.decode(hx, 'hex')
    r = hashlib.new('ripemd160', hx).digest()
    ripemd_hash = (codecs.encode(r, 'hex').decode("utf-8"))
    # print('RIPEMD: ',ripemd_hash)

    # 04 : add 00(version byte, mainnet is 00)
    hx4 = '00' + ripemd_hash

    # 05 : SHA256 double hasing
    hash = sha256(bytes.fromhex(hx4))
    hx5 = hash.hexdigest()
    hash = sha256(bytes.fromhex(hx5))
    hx6 = hash.hexdigest()

    # 06 : add 4byte for previous hash value
    hx = hx4 + hx6[0:8]
    # print('Double hash, prework: ',hx)

    # 07 : encoding base58
    unencoded_string = bytes.fromhex(hx)
    encoded_string = base58.b58encode(unencoded_string)
    hx7 = encoded_string.decode('utf-8')
    # print(hx7)

    return hx7

scriptpubkey_to_addr("0e3939be93bc0de35b81919efae7a5d3b8924b10c87a11017dc028c2cb231126")