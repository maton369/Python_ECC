# これまで登場した関数はec_lib.pyに保存されている
from ec_lib import scalar_multiply
from functools import partial

# 楕円曲線のパラメータ
a = -1
b = 2
p = 37

scalar_multiply = partial(scalar_multiply, a=a, p=p)

# 基準点の座標（公開パラメータ）
# 基準点を計算するプログラムで算出し、位数を計算しておく。
G = (25, 5)
n = 47


def ecdh(public_key, private_key):
    shared_secret = scalar_multiply(public_key, private_key)
    return shared_secret


def elgamal_enc(message, alice_private_key, bob_public_key):
    # M + abG の通常のベクトル和を計算
    m_x, m_y = message
    abG_x, abG_y = ecdh(bob_public_key, alice_private_key)
    cipher = ((m_x + abG_x) % p, (m_y + abG_y) % p)
    return cipher


def elgamal_dec(cipher, alice_public_key, bob_private_key):
    # M + abG - abG を計算して、平文に戻す
    c_x, c_y = cipher
    abG_x, abG_y = ecdh(alice_public_key, bob_private_key)
    return ((c_x - abG_x) % p, (c_y - abG_y) % p)


alice_private_key = 9
alice_public_key = aG = scalar_multiply(G, alice_private_key)
print(f"alice_private_key = {alice_private_key}, alice_public_key = {alice_public_key}")

bob_private_key = 23
bob_public_key = bG = scalar_multiply(G, bob_private_key)
print(f"bob_private_key = {bob_private_key}, bob_public_key = {bob_public_key}")

print()

message = (5, 10)
print(f"message = {message}")
cipher = elgamal_enc(message, alice_private_key, bob_public_key)
print(f"cipher = {cipher}, alice_public_key = {alice_public_key}")

plain_text = elgamal_dec(cipher, alice_public_key, bob_private_key)
print(f"plain_text = {plain_text}")
