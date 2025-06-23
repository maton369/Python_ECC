# これまで登場した関数はec_lib.pyに保存されている
from ec_lib import add_points, scalar_multiply, ecdsa_sign, ecdsa_verify
from functools import partial

# 楕円曲線のパラメータ
a = -1
b = 2
p = 37

add_points = partial(add_points, a=a, p=p)
scalar_multiply = partial(scalar_multiply, a=a, p=p)
ecdsa_sign = partial(ecdsa_sign, a=a, p=p)
ecdsa_verify = partial(ecdsa_verify, a=a, p=p)

# 基準点の座標（公開パラメータ）
G = (25, 5)
n = 47

# 秘密鍵の生成（ランダムな整数）
private_key = 13

# 公開鍵の生成
Q = scalar_multiply(G, private_key)
public_key = (G, Q)

# メッセージのハッシュ計算
message1 = "Hello, ECDSA!"
message2 = "Same k has vulnerability!!"
message_hash1 = int.from_bytes(message1.encode(), byteorder="big")
message_hash2 = int.from_bytes(message2.encode(), byteorder="big")

# 不適切な実装。固定のkを使って複数回署名
k = 17

signature1 = ecdsa_sign(message_hash1, G, k, private_key, n)
signature2 = ecdsa_sign(message_hash2, G, k, private_key, n)
verification1 = ecdsa_verify(signature1, message_hash1, G, Q, n)
verification2 = ecdsa_verify(signature2, message_hash2, G, Q, n)
print("signature", signature1, signature2)
print("verification", verification1, verification2)

r1, s1 = signature1
r2, s2 = signature2

# kの導出
k = ((message_hash1 - message_hash2) * pow((s1 - s2), -1, n)) % n
print("k =", k)

# 秘密鍵daの導出
da = ((s1 * k - message_hash1) * pow(r1, -1, n)) % n
print("da = ", da)
