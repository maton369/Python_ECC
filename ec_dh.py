# これまで登場した関数はec_lib.pyに保存されている
# scalar_multiply をインポート
from ec_lib import scalar_multiply
from functools import partial

# 楕円曲線のパラメータ a, b, p を定義（例: y^2 = x^3 + ax + b over F_p）
a = -1
b = 2
p = 37

# functools.partial を使って、scalar_multiply に a, p を事前に設定
# これで引数を減らして簡単に使えるようになる
scalar_multiply = partial(scalar_multiply, a=a, p=p)


# ECDH（楕円曲線 Diffie-Hellman）鍵共有を行う関数
# 相手の公開鍵と自分の秘密鍵から共有鍵を生成
def ecdh(public_key, private_key):
    shared_secret = scalar_multiply(public_key, private_key)
    return shared_secret


# 楕円曲線上の基準点（公開情報）
# G は全員が共有する点。位数 n も計算しておく（nG = O となるような n）
G = (25, 5)
n = 47

# アリスの秘密鍵（ランダムに選ぶ）
alice_private_key = 33
# アリスの公開鍵 = 秘密鍵 × G
alice_public_key = scalar_multiply(G, alice_private_key)
print(f"alice_private_key = {alice_private_key}, alice_public_key = {alice_public_key}")

# ボブの秘密鍵（ランダムに選ぶ）
bob_private_key = 29
# ボブの公開鍵 = 秘密鍵 × G
bob_public_key = scalar_multiply(G, bob_private_key)
print(f"bob_private_key = {bob_private_key}, bob_public_key = {bob_public_key}")

# アリスがボブの公開鍵と自分の秘密鍵から共有鍵を生成
alice_shared = ecdh(bob_public_key, alice_private_key)
# ボブがアリスの公開鍵と自分の秘密鍵から共有鍵を生成
bob_shared = ecdh(alice_public_key, bob_private_key)
# アリスとボブの共有鍵が一致するか確認（ECDH の基本性質）
assert alice_shared == bob_shared
print(f"alice_shared = {alice_shared}, bob_shared = {bob_shared}")
