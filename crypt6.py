from pygost.gost34112012 import GOST34112012 as GostHash
from pygost.gost3410 import CURVE_PARAMS  # p, q, a, b, x, y

from Eleptic import *

import asn1tools
import random


def GenSign(file):
    signeble_file = open(file, "rb")
    sing_file = open(file + "_sign.dat", 'wb')
    readFile = signeble_file.read()
    hash_message = GostHash(readFile).digest()
    e = int.from_bytes(hash_message, "big", signed=False) % curve.n

    r = 0
    s = 0
    while r == 0 or s == 0:
        k = random.randrange(1, curve.n)
        C = curve.mult(k, curve.g)
        r = C[0] % curve.n
        s = (r*d + k*e) % curve.n


    sign = gost_sign_file.encode('GostSignFile', dict(keyset=
    {
        'key': dict
            (
            algid=b'\x80\x06\x07\x00',
            test='gostSignKey',
            keydata=dict
            (
                qx = Q[0],
                qy = Q[1]
            ),
            param=dict
                (
                fieldparam=dict
                (
                    prime=curve.p
                ),
                curveparam=dict
                    (
                    a=curve.a,
                    b=curve.b
                ),
                genparam=dict
                    (
                    px=curve.g[0],
                    py=curve.g[1]
                ),
                q=curve.n
            ),
            ciphertext=dict
            (
                r=r,
                s=s
            )
        )
    }, last={}))
    sing_file.write(sign)
    sing_file.close()
    print("sign generated")
    return file + "_sign.dat"

def AuthSign(file, sign):
    sign_file = open(sign, 'rb')
    sign_data = sign_file.read()
    sign_str = gost_sign_file.decode('GostSignFile', sign_data)
    r = sign_str['keyset']['key']['ciphertext']['r']
    s = sign_str['keyset']['key']['ciphertext']['s']

    if r > curve.n or s > curve.n:
        return False

    source_file = open(file, "rb")
    readFile = source_file.read()
    hash = GostHash(readFile).digest()
    e = int.from_bytes(hash, "big", signed=False) % curve.n
    if e == 0:
        e = 1


    v = invert(e, curve.n)
    z1 = (s*v) % curve.n
    z2 = (-r*v) % curve.n

    C = curve.add(curve.mult(z1, curve.g), curve.mult(z2, Q))

    if  C[0] % curve.n == r:
        print("sign true")
        return True
    else:
        print("sign false")
        return False



gost_sign_file = asn1tools.compile_files('schemes/gost_sign.asn')
curve_param = CURVE_PARAMS["GostR3410_2012_TC26_ParamSetA"]

curve = EllipticCurve(
    int.from_bytes(curve_param[0], "big"),
    int.from_bytes(curve_param[2], "big"),
    int.from_bytes(curve_param[3], "big"),
    (
        int.from_bytes(curve_param[4], "big"),
        int.from_bytes(curve_param[5], "big")
    ),
    int.from_bytes(curve_param[1], "big")
)

d = random.randrange(1, curve.n)
Q = curve.mult(d, curve.g)


GenSign("otvety.txt")
AuthSign("otvety.txt", "otvety.txt_sign.dat")
AuthSign("otvety - Copy.txt", "otvety.txt_sign.dat")