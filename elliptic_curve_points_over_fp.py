import matplotlib.pyplot as plt

# 有限体の素数
p = 13


# 楕円曲線の右辺： y^2 ≡ x^3 + ax + b mod p
def elliptic_curve(x, a, b, p):
    return (x**3 + a * x + b) % p


# 有効な (x, y) を探す
def find_valid_points(a, b, p):
    points = []
    for x in range(p):
        y_squared = elliptic_curve(x, a, b, p)
        for y in range(p):
            if (y * y) % p == y_squared:
                points.append((x, y))
    return points


# 可視化する関数
def plot_points(points, a, b, p):
    if not points:
        print(f"a={a}, b={b} の楕円曲線に有効な点はありません")
        return

    x_vals, y_vals = zip(*points)

    plt.figure(figsize=(5, 5))
    plt.scatter(x_vals, y_vals, c="blue", s=100, edgecolors="black")

    plt.title(f"Elliptic Curve: y² ≡ x³ + {a}x + {b} mod {p}")
    plt.grid(True)
    plt.xticks(range(p))
    plt.yticks(range(p))
    plt.xlim(-1, p)
    plt.ylim(-1, p)
    plt.gca().set_aspect("equal", adjustable="box")
    plt.show()


# 探索対象の a, b
a_values = range(-2, 3)
b_values = range(-2, 3)

# すべての a, b に対してプロット（1つずつ）
for a in a_values:
    for b in b_values:
        points = find_valid_points(a, b, p)
        print(f"a={a}, b={b} → Points: {points}")
        plot_points(points, a, b, p)
