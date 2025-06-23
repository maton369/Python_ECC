# これまで登場した関数はec_lib.pyに保存されている
from ec_lib import add_points, scalar_multiply
from functools import partial
import random

# 楕円曲線のパラメータ
a = -1
b = 2
p = 37

add_points = partial(add_points, a=a, p=p)
scalar_multiply = partial(scalar_multiply, a=a, p=p)


def ecdsa_sign(M, G, k, n):
    P = scalar_multiply(G, k)
    x1, y1 = scalar_multiply(G, k)

    r = x1 % n
    if r == 0:
        raise ValueError("unlucky random number r")
    k_inv = pow(k, -1, n)

    s = ((M + (r * private_key) % n) * k_inv) % n
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


# 基準点の座標（公開パラメータ）
# 基準点を計算するプログラムで算出し、位数を計算しておく。
G = (25, 5)
n = 47

# 秘密鍵の生成（本来はn-1以下のランダムな整数を取る）
private_key = 13

# 公開鍵の生成
Q = scalar_multiply(G, private_key)
public_key = (G, Q)

# メッセージのハッシュ計算
message = "Hello, ECDSA!!"
message_hash = int.from_bytes(message.encode(), byteorder="big")
print("Message Hash:", message_hash)

# ランダムな値kの生成
k_list = list(range(1, n))
random.shuffle(k_list)

for k in k_list:
    # 署名の生成
    try:
        signature = ecdsa_sign(message_hash, G, k, n)
    except ValueError as e:
        print(e)
        continue
    r, s = signature
    print("signature", signature)

    # 署名の検証
    verification = ecdsa_verify(signature, message_hash, G, Q, n)

    print("verification:", verification)
    print("Signature Verified:", r == verification)
    break
