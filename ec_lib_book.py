import matplotlib.pyplot as plt


# 楕円曲線 y^2 ≡ x^3 + ax + b mod p 上の点加算
def add_points(P, Q, a, p):
    if Q == (None, None):
        return P
    if P == (None, None):
        return Q

    x_p, y_p = P
    x_q, y_q = Q

    if x_p == x_q and (y_p + y_q) % p == 0:
        return (None, None)

    if P == Q:
        m = ((3 * x_p**2 + a) * pow(2 * y_p, -1, p)) % p
    else:
        m = ((y_q - y_p) * pow(x_q - x_p, -1, p)) % p

    x_r = (m**2 - x_p - x_q) % p
    y_r = (m * (x_p - x_r) - y_p) % p

    return (x_r, y_r)


# スカラー倍（n * P）
def scalar_multiply(P, n, a, p):
    Q = (None, None)
    for i in range(n.bit_length()):
        if n & (1 << i):
            Q = add_points(Q, P, a, p)
        P = add_points(P, P, a, p)
    return Q


# 点の列挙（y^2 = x^3 + ax + b mod p）
def find_all_curve_points(a, b, p):
    points = []
    for x in range(p):
        rhs = (x**3 + a * x + b) % p
        for y in range(p):
            if (y * y) % p == rhs:
                points.append((x, y))
    return points


# 可視化関数
def plot_curve_and_multiples(all_points, multiples, a, b, p, G):
    plt.figure(figsize=(6, 6))

    # 全ての点（グレー）
    if all_points:
        xs, ys = zip(*all_points)
        plt.scatter(xs, ys, c="lightgray", s=80, label="All E(Fₚ) points")

    # スカラー倍による軌跡（青 → 赤）
    if multiples:
        mx, my = zip(*[pt for pt in multiples if pt != (None, None)])
        plt.scatter(mx, my, c="blue", s=100, edgecolors="black", label=f"<G={G}>")

        # 番号付け
        for i, pt in enumerate(multiples):
            if pt != (None, None):
                plt.text(pt[0] + 0.2, pt[1], f"{i + 1}G", fontsize=8, color="darkred")

    # 描画設定
    plt.title(f"ECC over Fₚ (a={a}, b={b}, p={p})")
    plt.xticks(range(p))
    plt.yticks(range(p))
    plt.grid(True)
    plt.gca().set_aspect("equal", adjustable="box")
    plt.legend()
    plt.xlim(-1, p)
    plt.ylim(-1, p)
    plt.show()


# -----------------------------
# 楕円曲線パラメータ
a = -1
b = 2
p = 13
G = (6, 11)  # 生成元
# -----------------------------

# 曲線上のすべての点
all_points = find_all_curve_points(a, b, p)

# <G> の生成（スカラー倍列挙）
multiples = []
for n in range(1, p + 2):  # 上限 = 位数+1程度で十分
    nG = scalar_multiply(G, n, a, p)
    multiples.append(nG)
    print(f"{n}G = {nG}")
    if nG == (None, None):
        break

print(f"<G_{G}> = {multiples}")

# 可視化
plot_curve_and_multiples(all_points, multiples, a, b, p, G)
