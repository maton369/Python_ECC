from pyasn1.type import univ, namedtype
from pyasn1.codec.der import encoder
from functools import partial
from ec_lib import *
import hashlib
import random

# 楕円曲線のパラメータ
# openssl ecparam -noout -text -param_enc explicit -name secp256k1
a = 0
b = 7
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

add_points = partial(add_points, a=a, p=p)
scalar_multiply = partial(scalar_multiply, a=a, p=p)


def ecdsa_sign(M, G, k, sk, n):
    P = scalar_multiply(G, k)
    x1, y1 = scalar_multiply(G, k)

    r = x1 % n
    if r == 0:
        raise ValueError("unlucky random number r")
    k_inv = pow(k, -1, n)

    s = ((M + (r * sk) % n) * k_inv) % n
    if s == 0:
        raise ValueError("unlucky random number s")
    return (r, s)


def ecdsa_verify(signature, M, G, Q, n):
    r, s = signature
    s_inv = pow(s, -1, n)

    u1 = (M * s_inv) % n
    u2 = (r * s_inv) % n

    r_x, r_y = add_points(scalar_multiply(G, u1), scalar_multiply(Q, u2))
    return r_x % n


class ECDSASignature(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("r", univ.Integer()),
        namedtype.NamedType("s", univ.Integer()),
    )


# 1. 鍵の生成
# 秘密鍵の生成（ランダムな整数）
# openssl ecparam -name prime256v1 -genkey -out private_key.pem
# openssl ec -in private_key.pem -text -noout
private_key = 0xFBC6EBA614815BC85E3898A593BBE4BF27498F1186D0559101C152CD91685E1C

# 公開鍵の生成
public_key = scalar_multiply(G, private_key)
public_x, public_y = public_key
# print('public_key:', (hex(public_x), hex(public_y)))

# 2. メッセージのハッシュ計算
message = "Hello, ECDSA!"
message_hash = hashlib.sha256(message.encode()).digest()

# 16進数の整数に変換
message_hash = int.from_bytes(message_hash, byteorder="big")
print("Message Hash:", hex(message_hash))

# 乱数kを選ぶ
k = random.randint(1, n)

# 3. 署名の生成
# openssl dgst -sha256 -sign private_key.pem -out signature.bin data.txt
signature = ecdsa_sign(message_hash, G, k, private_key, n)
r, s = signature
print("signature:", (hex(r), hex(s)))

# 作成した署名をasn1フォーマットに変換し、ファイルに保存
asn1_signature = ECDSASignature()
asn1_signature["r"] = r
asn1_signature["s"] = s

der_signature = encoder.encode(asn1_signature)
with open("signature_secp256k1.bin", "wb") as f:
    f.write(der_signature)

# openssl asn1parse -inform DER -in signature.bin
# signature = (0x6CFBD806FFBFFF93CAC3EA99A809F89004D2FFB92ECDDC70EF03BE9785AC02E9, 0x5FF1AE96F102C17C1EB4266B114B9AF2F5CE3D7942EC53B888F2E86F0E103BFA)
r, s = signature

# 4. 署名の検証
# openssl dgst -sha256 -verify public_key.pem -signature signature.bin data.txt
verification = ecdsa_verify(signature, message_hash, G, public_key, n)

print("verification:", hex(verification))
print("Signature Verified:", r == verification)
