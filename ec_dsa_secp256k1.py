# ECDSA 署名処理に必要なライブラリのインポート
from pyasn1.type import univ, namedtype  # ASN.1構造の定義用
from pyasn1.codec.der import encoder  # DERエンコード用
from functools import partial  # 関数の引数を部分的に固定するため
from ec_lib import *  # 楕円曲線演算の実装（add_points, scalar_multiply など）
import hashlib  # ハッシュ関数（SHA-256）
import random  # ランダムな nonce k を生成するため

# 楕円曲線 secp256k1 のパラメータ（OpenSSL の出力より取得）
# y^2 = x^3 + 7 over F_p
a = 0
b = 7
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F  # 素数p（フィールド）

# 楕円曲線の基準点（G = (Gx, Gy)）
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)

# 楕円曲線の位数（基準点の巡回周期）
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# 関数に a, p を固定する（以降は引数を簡略に呼び出せる）
add_points = partial(add_points, a=a, p=p)
scalar_multiply = partial(scalar_multiply, a=a, p=p)


# ECDSA 署名生成関数
def ecdsa_sign(M, G, k, sk, n):
    # k を使って kG を計算し、その x 座標から r を取得
    x1, y1 = scalar_multiply(G, k)
    r = x1 % n
    if r == 0:
        raise ValueError("unlucky random number r")  # r が 0 の場合は再試行

    # k の逆元を n を法として計算
    k_inv = pow(k, -1, n)

    # s = k⁻¹(M + r * sk) mod n
    s = ((M + (r * sk) % n) * k_inv) % n
    if s == 0:
        raise ValueError("unlucky random number s")  # s が 0 の場合も再試行
    return (r, s)


# ECDSA 検証関数
def ecdsa_verify(signature, M, G, Q, n):
    r, s = signature
    s_inv = pow(s, -1, n)  # s の逆元を計算

    # u1 = M * s⁻¹ mod n、u2 = r * s⁻¹ mod n
    u1 = (M * s_inv) % n
    u2 = (r * s_inv) % n

    # R = u1 * G + u2 * Q を計算し、r ≡ R.x mod n であることを確認
    r_x, r_y = add_points(scalar_multiply(G, u1), scalar_multiply(Q, u2))
    return r_x % n


# ASN.1 形式で署名を構造化するためのクラス定義
class ECDSASignature(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("r", univ.Integer()),
        namedtype.NamedType("s", univ.Integer()),
    )


# 1. 鍵の生成（ここでは固定の秘密鍵を使用）
# 実際にはセキュアな乱数生成器でランダムに作成する必要あり
private_key = 0xFBC6EBA614815BC85E3898A593BBE4BF27498F1186D0559101C152CD91685E1C

# 公開鍵 Q = private_key * G
public_key = scalar_multiply(G, private_key)
public_x, public_y = public_key

# 2. メッセージのハッシュ計算（SHA-256）
message = "Hello, ECDSA!"
message_hash = hashlib.sha256(message.encode()).digest()

# ハッシュを整数に変換（ECDSAでは整数として扱う必要がある）
message_hash = int.from_bytes(message_hash, byteorder="big")
print("Message Hash:", hex(message_hash))

# 署名用のランダムな nonce k を生成（1 ≤ k < n）
k = random.randint(1, n)

# 3. 署名の生成
signature = ecdsa_sign(message_hash, G, k, private_key, n)
r, s = signature
print("signature:", (hex(r), hex(s)))

# 署名を ASN.1 / DER 形式にエンコードしてバイナリファイルに保存
asn1_signature = ECDSASignature()
asn1_signature["r"] = r
asn1_signature["s"] = s

der_signature = encoder.encode(asn1_signature)
with open("signature_secp256k1.bin", "wb") as f:
    f.write(der_signature)

# 4. 署名の検証
verification = ecdsa_verify(signature, message_hash, G, public_key, n)
print("verification:", hex(verification))
print("Signature Verified:", r == verification)
