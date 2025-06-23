# これまで登場した関数はec_lib.pyに保存されている
from ec_lib import scalar_multiply
from functools import partial

# 楕円曲線のパラメータ
a = -1
b = 2
p = 37

scalar_multiply = partial(scalar_multiply, a=a, p=p)


def ecdh(public_key, private_key):
    shared_secret = scalar_multiply(public_key, private_key)
    return shared_secret


# 基準点の座標（公開パラメータ）
# 基準点を計算するプログラムで算出し、位数を計算しておく。
G = (25, 5)
n = 47

alice_private_key = 33
alice_public_key = scalar_multiply(G, alice_private_key)
print(f"alice_private_key = {alice_private_key}, alice_public_key = {alice_public_key}")

bob_private_key = 29
bob_public_key = scalar_multiply(G, bob_private_key)
print(f"bob_private_key = {bob_private_key}, bob_public_key = {bob_public_key}")

alice_shared = ecdh(bob_public_key, alice_private_key)
bob_shared = ecdh(alice_public_key, bob_private_key)
assert alice_shared == bob_shared
print(f"alice_shared = {alice_shared}, bob_shared = {bob_shared}")
