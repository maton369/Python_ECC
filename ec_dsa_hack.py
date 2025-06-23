# これまで登場した関数はec_lib.pyに保存されている
# 楕円曲線の加算、スカラー倍、署名、検証関数をインポート
from ec_lib import add_points, scalar_multiply, ecdsa_sign, ecdsa_verify
from functools import partial

# 楕円曲線のパラメータ（例：y^2 = x^3 + ax + b over F_p）
a = -1
b = 2
p = 37

# a, p を固定値として部分適用し、使いやすくする
add_points = partial(add_points, a=a, p=p)
scalar_multiply = partial(scalar_multiply, a=a, p=p)
ecdsa_sign = partial(ecdsa_sign, a=a, p=p)
ecdsa_verify = partial(ecdsa_verify, a=a, p=p)

# 基準点（公開パラメータ G）と、その位数 n
G = (25, 5)
n = 47  # 位数（nG = O となる最小の正の整数）

# 秘密鍵（本来はランダムに生成されるが、今回は固定で使用）
private_key = 13

# 公開鍵 Q = dG を計算
Q = scalar_multiply(G, private_key)
public_key = (G, Q)  # 必要なら公開パラメータと合わせてパッケージ化できる

# メッセージの準備とハッシュ値の計算（ここでは簡単に文字列→整数変換）
message1 = "Hello, ECDSA!"
message2 = "Same k has vulnerability!!"
message_hash1 = int.from_bytes(message1.encode(), byteorder="big")
message_hash2 = int.from_bytes(message2.encode(), byteorder="big")

# ❌ 危険：同じ k を使って異なるメッセージに署名（これは大きな脆弱性）
k = 17

# メッセージ1とメッセージ2の署名を同じ k で生成
signature1 = ecdsa_sign(message_hash1, G, k, private_key, n)
signature2 = ecdsa_sign(message_hash2, G, k, private_key, n)

# 各署名を検証（有効かどうか）
verification1 = ecdsa_verify(signature1, message_hash1, G, Q, n)
verification2 = ecdsa_verify(signature2, message_hash2, G, Q, n)

print("signature", signature1, signature2)
print("verification", verification1, verification2)

# 各署名から (r, s) を取り出す
r1, s1 = signature1
r2, s2 = signature2

# 🔓【攻撃者の視点】同じ k を使って生成された 2 つの署名から k を導出
# k = (H(m1) - H(m2)) / (s1 - s2) mod n
k = ((message_hash1 - message_hash2) * pow((s1 - s2), -1, n)) % n
print("k =", k)

# 🔓 秘密鍵（private_key = dA）を導出
# d = (s * k - H(m)) / r mod n
da = ((s1 * k - message_hash1) * pow(r1, -1, n)) % n
print("da = ", da)
