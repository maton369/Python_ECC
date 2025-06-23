# 2つの楕円曲線上の点を加算する関数
# P, Q: 加算対象の点（x, y）または無限遠点 (None, None)
# a: 曲線の係数、p: 素数（有限体）
def add_points(P, Q, a, p):
    if Q == (None, None):
        # Q が無限遠点の場合、P + O = P
        return P
    if P == (None, None):
        # P が無限遠点の場合、O + Q = Q
        return Q

    x_p, y_p = P
    x_q, y_q = Q

    # P と Q の x 座標が同じで、y 座標の和が 0（mod p）の場合、加算結果は無限遠点
    if x_p == x_q and ((y_p + y_q) % p == 0):
        return (None, None)

    # P == Q の場合、接線を使った接線法
    if P == Q:
        m = ((3 * x_p**2 + a) * pow(2 * y_p, -1, p)) % p
    else:
        # P ≠ Q の場合、2点を結ぶ直線の傾き
        m = ((y_q - y_p) * pow(x_q - x_p, -1, p)) % p

    # 加算結果 R = (x_r, y_r) を計算
    x_r = (m**2 - x_p - x_q) % p
    y_r = (m * (x_p - x_r) - y_p) % p

    return (x_r, y_r)


# スカラー倍の関数
# 点 P に対して、n 倍（nP）を計算
# a: 曲線の係数、p: 素数
def scalar_multiply(P, n, a, p):
    Q = (None, None)  # 無限遠点で初期化
    for i in range(n.bit_length()):
        if n & (1 << i):  # n の i ビット目が立っている場合
            Q = add_points(Q, P, a, p)
        P = add_points(P, P, a, p)  # P を毎回2倍していく
    return Q


# ECDH 鍵共有: 秘密鍵と相手の公開鍵を使って共有秘密を生成
def ecdh(public_key, private_key):
    shared_secret = scalar_multiply(public_key, private_key)
    return shared_secret


# ECDSA 署名関数
# M: メッセージハッシュ、G: 基点、k: 一時的な乱数、sk: 秘密鍵、n: 曲線の位数、a/p: 曲線パラメータ
def ecdsa_sign(M, G, k, sk, n, a, p):
    # ランダム値 k に対して P = kG を計算
    P = scalar_multiply(G, k, a, p)
    x1, y1 = P

    # r を P の x 座標の mod n で定義
    r = x1 % n
    if r == 0:
        raise ValueError("unlucky random number r")

    # k の逆元を mod n で計算
    k_inv = pow(k, -1, n)

    # 署名の s を計算
    s = ((M + (r * sk) % n) * k_inv) % n
    if s == 0:
        raise ValueError("unlucky random number s")
    return (r, s)


# ECDSA 署名検証関数
# signature: (r, s)、M: メッセージハッシュ、G: 基点、Q: 公開鍵、n: 位数、a/p: 曲線パラメータ
def ecdsa_verify(signature, M, G, Q, n, a, p):
    r, s = signature

    # s の逆元を計算
    s_inv = pow(s, -1, n)

    # u1 = M/s, u2 = r/s
    u1 = (M * s_inv) % n
    u2 = (r * s_inv) % n

    # R = u1 * G + u2 * Q を計算
    r_x, r_y = add_points(
        scalar_multiply(G, u1, a, p), scalar_multiply(Q, u2, a, p), a, p
    )

    # 計算された R.x mod n が r と一致すれば署名は正当
    return r_x % n
