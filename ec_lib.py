# 2つの楕円曲線上の点を加算する関数
def add_points(P, Q, a, p):
    if Q == (None, None):
        # P + O = P
        return P
    if P == (None, None):
        # Q + O = Q
        return Q

    x_p, y_p = P
    x_q, y_q = Q

    # 条件1
    if x_p == x_q and ((y_p + y_q) % p == 0):
        return (None, None)

    # 条件2
    if P == Q:
        m = ((3 * x_p**2 + a) * pow(2 * y_p, -1, p)) % p
    else:
        m = ((y_q - y_p) * pow(x_q - x_p, -1, p)) % p

    x_r = (m**2 - x_p - x_q) % p
    y_r = (m * (x_p - x_r) - y_p) % p

    return (x_r, y_r)


# スカラー倍の関数
def scalar_multiply(P, n, a, p):
    Q = (None, None)
    for i in range(n.bit_length()):
        if n & (1 << i):
            Q = add_points(Q, P, a, p)
        P = add_points(P, P, a, p)
    return Q


def ecdh(public_key, private_key):
    shared_secret = scalar_multiply(public_key, private_key)
    return shared_secret


def ecdsa_sign(M, G, k, sk, n, a, p):
    P = scalar_multiply(G, k, a, p)
    x1, y1 = scalar_multiply(G, k, a, p)

    r = x1 % n
    if r == 0:
        raise ValueError("unlucky random number r")
    k_inv = pow(k, -1, n)

    s = ((M + (r * sk) % n) * k_inv) % n
    if s == 0:
        raise ValueError("unlucky random number s")
    return (r, s)


def ecdsa_verify(signature, M, G, Q, n, a, p):
    r, s = signature
    s_inv = pow(s, -1, n)

    u1 = (M * s_inv) % n
    u2 = (r * s_inv) % n

    r_x, r_y = add_points(
        scalar_multiply(G, u1, a, p), scalar_multiply(Q, u2, a, p), a, p
    )
    return r_x % n
