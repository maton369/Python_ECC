# これまで登場した関数はec_lib.pyに保存されている
# 楕円曲線上の加算、スカラー倍関数をインポート
from ec_lib import add_points, scalar_multiply
from functools import partial
import random

# 楕円曲線のパラメータ a, b, p を定義（例: y^2 = x^3 + ax + b over F_p）
a = -1
b = 2
p = 37

# 楕円曲線演算を簡略化するために、a, p を固定した部分適用関数を作成
add_points = partial(add_points, a=a, p=p)
scalar_multiply = partial(scalar_multiply, a=a, p=p)


# ECDSA 署名関数
# M: メッセージハッシュ、G: 基点、k: ランダム値、n: 曲線の位数
# 署名 (r, s) を返す
def ecdsa_sign(M, G, k, n):
    # k を使って P = kG を計算し、x 座標を取得
    P = scalar_multiply(G, k)
    x1, y1 = scalar_multiply(G, k)  # 冗長な再計算（1行にまとめられる）

    # r = x 座標の mod n を取る
    r = x1 % n
    if r == 0:
        # r が 0 の場合は再試行（運の悪い乱数）
        raise ValueError("unlucky random number r")

    # k の逆元を n を法として計算
    k_inv = pow(k, -1, n)

    # s を計算：s = k⁻¹(M + r * 秘密鍵) mod n
    s = ((M + (r * private_key) % n) * k_inv) % n
    if s == 0:
        # s が 0 の場合も再試行
        raise ValueError("unlucky random number s")
    return (r, s)


# ECDSA 検証関数
# signature: (r, s)、M: メッセージハッシュ、G: 基点、Q: 公開鍵、n: 曲線位数
# r ≡ x1 mod n を満たすかどうかで正当性を判定
def ecdsa_verify(signature, M, G, Q, n):
    r, s = signature
    # s の逆元を計算
    s_inv = pow(s, -1, n)

    # u1 = M * s⁻¹ mod n、u2 = r * s⁻¹ mod n
    u1 = (M * s_inv) % n
    u2 = (r * s_inv) % n

    # R = u1 * G + u2 * Q を計算して、x 座標の mod n が r に一致するか確認
    r_x, r_y = add_points(scalar_multiply(G, u1), scalar_multiply(Q, u2))
    return r_x % n


# 基準点の座標（公開パラメータ）
# 基準点を計算するプログラムで算出し、位数を計算しておく。
G = (25, 5)
n = 47

# 秘密鍵（乱数で生成、本来はセキュアな方法で生成する）
private_key = 13

# 公開鍵 Q = 秘密鍵 × G を計算
Q = scalar_multiply(G, private_key)
public_key = (G, Q)

# メッセージ文字列をハッシュに変換（ここでは簡易にバイト列を整数化）
message = "Hello, ECDSA!!"
message_hash = int.from_bytes(message.encode(), byteorder="big")
print("Message Hash:", message_hash)

# 署名用に k を 1〜n-1 からランダムにシャッフルして選ぶ
k_list = list(range(1, n))
random.shuffle(k_list)

for k in k_list:
    # k ごとに署名を試みる。運が悪ければやり直す（r や s が 0）
    try:
        signature = ecdsa_sign(message_hash, G, k, n)
    except ValueError as e:
        # 例外が出た場合は次の k で再試行
        print(e)
        continue

    r, s = signature
    print("signature", signature)

    # 署名を検証
    verification = ecdsa_verify(signature, message_hash, G, Q, n)

    # r と検証結果が一致すれば署名は正当
    print("verification:", verification)
    print("Signature Verified:", r == verification)
    break
