+++
title = "CMRGを予測する"
date = 2022-06-17

[taxonomies]
tags = ["CTF", "Crypto", "RNG", "Lattice", "LLL"]
+++

## 序文

いつものupsolveのネタが尽きてきたので重めの問題(pbctf 2021 - Yet Another PRNG)をやろうとしたら、参考となっている論文が面白かったので紹介するついでにPoCを書きます

<!-- more -->

## CMRGと問題設定

今回解析するRNGはCMRG("Combined Multiple Recursive Generators")というやつで、論文中では次のように状態$x_i,y_i$の更新と出力$z_i$が定義されている。

$$
\begin{aligned}
x_i &= a_{11}x_{i-1}+a_{12}x_{i-2}+a{13}x_{i-3} \mod m_1 \cr
y_i &= a_{21}y_{i-1}+a_{22}y_{i-2}+a{23}y_{i-3} \mod m_2 \cr
z_i &= x_i - y_i \mod m_1
\end{aligned}
$$

問題設定として、$a_{11}, a_{12}, a_{13}, a_{21}, a_{22}, a_{23}, m_1, m_2$は既知であり、ここからある程度(今回の方法による最低値は7個)の出力$z_i$を得てから、後続の出力を予測する。

## CRT

上記の通り、CMRGは実質的に2つの線形なRNGを組み合わせている。もし、$m_1, m_2$が互いに素(大抵は周期を伸ばすために$m_1, m_2$が素数が使われるはずなので満たされる)であれば、中国人剰余定理を使って次のような$A,B,C$を求めて2つのRNGを1つのものとして扱う事が出来る

$$
\begin{aligned}
A \equiv a_{11} \mod m_1, \ A\equiv a_{21} \mod m_2 \cr
B \equiv a_{21} \mod m_1, \ A\equiv a_{22} \mod m_2 \cr
C \equiv a_{31} \mod m_1, \ A\equiv a_{23} \mod m_2 \cr
\end{aligned}
$$

この$A,B,C$に対して、$X_i \equiv x_i \mod m_1, X_i \equiv y_i \mod m_2$とすれば次が成り立つ。

$$
X_i \equiv AX_{i-1} + BX_{i-2} + CX_{i-3} \mod m_1m_2
$$

## 格子に落とす式

上記で定義した$X_i$とそれに関する式に対して$X_i$を$x_i$で表すことが出来れば、$m_1m_2$を法としている式に対して、$x_i \approx \sqrt{m_1m_2}$が現れ、これは式中の項の中で比較的小さい値となるから格子の問題に落とすことが出来る予感がする。というわけで試みる。

ここで$z_i' \coloneqq x_i - y_i$と定義する。通常の出力$z_i$との違いは$m_1$で法を取っているかいないかである。

出力の式を見ると$z_i = x_i- y_i \mod m_1$となっているが、$m_1$と$m_2$が近いと仮定すれば、$-m_1 < x_i - y_i < m_1$が成り立つので、$z_i = x_i - y_i \lor z_i = x_i - y_i + m_1$としてよい。よって、$z_i'$は出力$z_i$に対して2択であり、実際得た出力に対して全探索することでどこかで正しい$z_i'$に当たる。よって、以下では$z_i'$を引き当てた場合を仮定する。

$X_i$の定義から、$X_i = k_i m_1 + x_i = k_i'm_2 + y_i$となる整数$0\leq k_i <m_2, 0\leq k_i' < m_1$が存在する。中辺と右辺を変形すると次が成り立つ

$$
z_i' = x_i - y_i = k_i'm_2 - k_im_1
$$

更に$m_2$で法をとると、$z_i' \equiv -k_im_1\mod m_2$が成り立つから、$k_i$について解くと$k_i \equiv -\frac{z_i'}{m_1} \mod m_2$となる。論文に従って、$u \coloneqq m_1^{-1} \mod m_2$とおいて、$k_i \equiv -um_1 \mod m_2$とする。

よって、このような$k_i$を用いれば次が成り立つ

$$
k_{i+3}m_1+x_{i+3} - A(k_{i+2}m_1 + x_{i+2}) - B(k_{i+1}m_1 + x_{i+1}) - C(k_im_1 + x_i) \equiv 0 \mod m_1m_2
$$

この式中で$x_{i+3}, x_{i+2}, x_{i+1}, x_i$以外の項の大きさは$m_1m_2$と同程度であるが、これらは$\sqrt{m_1m_2}$程度であるから有意に小さい。よってLLL等の基底簡約アルゴリズムで短いベクトルを求めればその中に$x_{i+3}, x_{i+2}, x_{i+1}, x_i$が現れるような格子を構成出来る可能性が見えてくる。

## LLLで倒す

初期状態を$x_{-3}, x_{-2}, x_{-1}, y_{-3}, y_{-2}, y_{-1}$として7つの出力$z_0, z_1, z_2, z_3, z_4, z_5, z_6$を得る。簡単のためそれぞれの$z_i$に対して$z_i'$を当てられたとする(よって$k_i$は全て計算できる)。

この時、先程の式から$x_3$は$x_0, x_1, x_2$を変数として表すことが出来る。具体的には次のようになる。

$$
\begin{aligned}
x_3 &\equiv A(k_{2}m_1 + x_{2}) + B(k_{1}m_1 + x_{1}) + C(k_im_1 + x_0) - k_3m_1 \mod m_1m_2\cr
&\equiv Ax_2 + Bx_1 + Cx_0 + D_3 \mod m_1m_2
\end{aligned}
$$

ここで、$D_3$は定数項を全部足したものとする。また、$D_i$に関しては次のような関係がある。

$$
D_{i} \equiv -k_{i}m_1 + Ak_{i-1}m_1 + Bk_{i-2}m_1 + Ck_{i-3}m_1 \mod m_1m_2
$$

同様にして$x_4$は$x_3, x_2, x_1$で表すことが出来るが、$x_3$が$x_2,x_1,x_0$で表すことが出来たので$x_4$も同様である。

このようにして$x_3, x_4, x_5,x_6$はいずれも$x_0, x_1, x_2$の線形多項式で表すことが出来るので次のようにおく。

$$
x_i \equiv c_{i,0}x_0 + c_{i,1}x_1 + c_{i,2}x_2 + D_i \mod m_1m_2
$$

法$m_1m_2$を外して、商を$l_i$とおくと次のようになる

$$
x_i = c_{i,0}x_0 + c_{i,1}x_1 + c_{i,2}x_2 + D_i - l_im_1m_2
$$

先に述べたように、$x_i$が短いベクトルの成分として現れるような格子を組んで簡約し、これらを求めることを考える。今回は次のような格子を組んだ。

$$
\begin{pmatrix}
 1 & & & & c_{3,0} & c_{4,0} & c_{5,0} & c_{6,0} \cr
 & 1 & & & c_{3,1} & c_{4,1} & c_{5,1} & c_{6,1} \cr
 & & 1 & & c_{3,2} & c_{4,2} & c_{5,2} & c_{6,2} \cr
 & & & 2^{32} & c_{3,3} & c_{4,3} & c_{5,3} & c_{6,3} \cr
 & & & & m_1m_2 & \cr
 & & & & & m_1m_2 & \cr
 & & & & & & m_1m_2 & \cr
 & & & & & & & m_1m_2 \cr
\end{pmatrix}
$$

これに左から$(x_0, x_1, x_2, 1, l_3, l_4, l_5, l_6)$を掛けると、$(x_0, x_1, x_2, 2^{32}, x_3, x_4, x_5, x_6)$が現れる。

この格子の体積は$2^{32}(m_1m_2)^4$であるので、LLLで出てくる基底の大きさは(だいたい)$2^4(m_1m_2)^{\frac 12} \approx 2^4\cdot2^{32}$より小さくなり、$(x_0, x_1, x_2, 2^{32}, x_3, x_4, x_5, x_6)$のノルムがだいたいこのぐらいなので出てくれると期待出来る。

$x_0, x_1, x_2$が求められれば、$z_0', z_1', z_2'$から$y_0, y_1, y_2$を求めることが出来るので以降の出力を完全に予測出来る。

### 係数と定数項を求める

各$x_i$に対して、$x_0, x_1, x_2$の係数$c_{i,0}, c_{i,1}, c_{i,2}$と定数項$D_i$を手計算で求めようとすると骨が折れすぎるので次のスクリプトで求めた。

```python
A = var("A")
B = var("B")
C = var("C")

Ds = [var(f"D{i}") for i in range(4)]
vars = [var(f"v{i}") for i in range(3)]

for i in range(3, 3 + 4):
    Ds.append(var(f"D{i}"))
    vars.append(A*vars[-1] + B*vars[-2] + C*vars[-3] + Ds[-1])

for i, v in enumerate(vars):
    if i < 3:
        continue
    c_v0 = v.list(vars[0])[1]
    c_v1 = v.list(vars[1])[1]
    c_v2 = v.list(vars[2])[1]
    constant = v.list(vars[0])[0].list(vars[1])[0].list(vars[2])[0]
    coeffs_dump = f"""{i}:
    v0_c = {c_v0}
    v1_c = {c_v1}
    v2_c = {c_v2}
    constant = {constant}"""

    print(coeffs_dump)
```

これを実行すると次のような結果になり、各係数が得られる

```
3:
    v0_c = C
    v1_c = B
    v2_c = A
    constant = D3
4:
    v0_c = A*C
    v1_c = A*B + C
    v2_c = A^2 + B
    constant = A*D3 + D4
5:
    v0_c = A^2*C + B*C
    v1_c = A^2*B + B^2 + A*C
    v2_c = A^3 + 2*A*B + C
    constant = A^2*D3 + B*D3 + A*D4 + D5
6:
    v0_c = A^3*C + 2*A*B*C + C^2
    v1_c = A^3*B + 2*A*B^2 + A^2*C + 2*B*C
    v2_c = A^4 + 3*A^2*B + B^2 + 2*A*C
    constant = A^3*D3 + 2*A*B*D3 + A^2*D4 + C*D3 + B*D4 + A*D5 + D6

```

余談だが、参考にした論文(参考文献に記載)では、これと似たような格子を組んで簡約しているようだが、論文に掲載されている格子は計算ミスで値が誤っているようである。

## Code

PRNG内で幾つかのチェックをしており見にくいが、最終的に7つの$z_i'$と既知の値のみから$x_0, x_1, x_2$を復元している

```python
# based on https://eprint.iacr.org/2021/1204.pdf

import random


# ref and parameter stolen from: http://www.secmem.org/blog/2021/10/24/Breaking-Combined-Multiple-Recursive-Generators/
class PRNG:
    def __init__(self) -> None:
        self.m1 = 2**32 - 107
        self.m2 = 2**32 - 5
        self.N = self.m1 * self.m2

        assert is_prime(self.m1)
        assert is_prime(self.m2)

        self.a1 = [random.getrandbits(32) for _ in range(3)]
        self.a2 = [random.getrandbits(32) for _ in range(3)]

        self.__x1 = [random.getrandbits(32) for _ in range(3)]
        self.__x2 = [random.getrandbits(32) for _ in range(3)]

        # debug parameters

        # CRT
        self.A = crt([self.a1[0], self.a2[0]], [self.m1, self.m2])
        self.B = crt([self.a1[1], self.a2[1]], [self.m1, self.m2])
        self.C = crt([self.a1[2], self.a2[2]], [self.m1, self.m2])

        self.Ds = []

        self.__answer1 = []
        self.__answer2 = []

        self.u = power_mod(self.m1, -1, self.m2)

        # z' in paper
        # self.__z = [x - y for x,y in zip(self.__x1, self.__x2)]
        # self.__k = [-z * self.u % self.m2 for z in self.__z]
        self.__z = []
        self.__k = []


    def next(self, i=None) -> int:
        new_x1 = sum([x * y for x, y in zip(reversed(self.a1), self.__x1)]) % self.m1
        new_x2 = sum([x * y for x, y in zip(reversed(self.a2), self.__x2)]) % self.m2


        new_z = new_x1 - new_x2
        new_k = -new_z * self.u % self.m2
        # t1 = new_k * self.m1 + new_x1
        # t2 = self.A * (self.__k[2] * self.m1 + self.__x1[2])
        # t3 = self.B * (self.__k[1] * self.m1 + self.__x1[1])
        # t4 = self.C * (self.__k[0] * self.m1 + self.__x1[0])
        # P = (t1 - t2 - t3 - t4) % (self.m1 * self.m2)

        if i is not None and i > 2:
            D = (-new_k + self.A * self.__k[-1] + self.B * self.__k[-2] +self.C * self.__k[-3]) * self.m1 % (self.N)
            self.Ds.append(D)
            P = (self.A * self.__x1[2] + self.B * self.__x1[1] + self.C * self.__x1[0] + D) % (self.N)
            assert P == new_x1

        # rough check
        if i in [3, 4, 5, 6]:
            v0, v1, v2 = self.__answer1[:3]
            A, B, C = self.A, self.B, self.C
            Ds = self.Ds
            if i == 3:
                v0_c = C
                v1_c = B
                v2_c = A
                constant = self.Ds[0]
            elif i == 4:
                v0_c = A * C
                v1_c = A * B + C
                v2_c = A**2 + B
                constant = A * self.Ds[0] + self.Ds[1]
            elif i == 5:
                v0_c = A^2*C + B*C
                v1_c = A^2*B + B^2 + A*C
                v2_c = A^3 + 2*A*B + C
                constant = A^2*Ds[0] + B*Ds[0] + A*Ds[1] + Ds[2]
            elif i == 6:
                v0_c = A^3*C + 2*A*B*C + C^2
                v1_c = A^3*B + 2*A*B^2 + A^2*C + 2*B*C
                v2_c = A^4 + 3*A^2*B + B^2 + 2*A*C
                constant = A^3*Ds[0] + 2*A*B*Ds[0] + A^2*Ds[1] + C*Ds[0] + B*Ds[1] + A*Ds[2] + Ds[3]

            rhs = (v0_c * v0 + v1_c * v1 + v2_c * v2 + constant) % self.N
            assert rhs, new_x1


        self.__z.append(new_z)
        self.__k.append(new_k)

        self.__answer1.append(new_x1)
        self.__answer2.append(new_x2)

        self.__x1 = self.__x1[1:] + [new_x1]
        self.__x2 = self.__x2[1:] + [new_x2]

        # assumption: perfect guess z'
        return new_z

        # return (new_x1 - new_x2) % self.m1

    def check(self, zs, ks, Ds):
        res1 = self.__z == zs
        res2 = self.__k == ks
        res3 = self.Ds == Ds

        return (res1, res2, res3)


    def get_answer(self):
        return self.__answer1, self.__answer2


# cheating (gueesing z' is success)
prng = PRNG()

# public parameters
m1 = prng.m1
m2 = prng.m2
N = m1 * m2
a1 = prng.a1
a2 = prng.a2
u = power_mod(m1, -1, m2)

print("=============== Exploit ===============")

A = crt([a1[0], a2[0]], [m1, m2])
B = crt([a1[1], a2[1]], [m1, m2])
C = crt([a1[2], a2[2]], [m1, m2])
Ds = []
ks = []
zs = []

for i in range(10):
    z = prng.next(i)
    k = -z * u % m2

    if i >= 3:
        D = (-k + A * ks[-1] + B * ks[-2] + C * ks[-3]) * m1 % N
        Ds.append(D)

    zs.append(z)
    ks.append(k)

# check
res = all(prng.check(zs, ks, Ds))
assert res

# calculation x0, x1, x2
size = 8
mat = [
    [0 for _ in range(size)] for _ in range(size)
]

for i in range(3):
    mat[i][i] = 1

mat[3][3] = 2^32

for i in range(4):
    mat[4+i][4+i] = N

# v0_c, v1_c, v2_c, constant
polys = [
    [C, B, A, Ds[0]],
    [A * C, A * B + C, A**2 + B, A * Ds[0] + Ds[1]],
    [A^2*C + B*C, A^2*B + B^2 + A*C, A^3 + 2*A*B + C, A^2*Ds[0] + B*Ds[0] + A*Ds[1] + Ds[2]],
    [A^3*C + 2*A*B*C + C^2, A^3*B + 2*A*B^2 + A^2*C + 2*B*C, A^4 + 3*A^2*B + B^2 + 2*A*C, A^3*Ds[0] + 2*A*B*Ds[0] + A^2*Ds[1] + C*Ds[0] + B*Ds[1] + A*Ds[2] + Ds[3]]
]

def dump_mat(m):
    for row in m:
        print(row)

for i, poly in enumerate(polys):
    for j, v in enumerate(poly):
        mat[j][i+4] = v % N

M = matrix(ZZ, mat)

for b in M.LLL():
    answer = []
    _ys = []
    if abs(b[3]) == 2**32:
        for x in b[:3]:
            answer.append(abs(x))

        for x, z in zip(answer, zs):
            _ys.append(x - z)

        x = sum([_x * _a for _x, _a in zip(answer, reversed(a1))]) % m1
        y = sum([_y * _b for _y, _b in zip(_ys, reversed(a2))]) % m2

        if x - y == zs[3]:
            print(answer, _ys)
            break


true_x, true_y = prng.get_answer()
print(f"[{answer == true_x[:3]}] answer: {true_x[:3]}")
print(f"[{_ys == true_y[:3]}] answer: {true_y[:3]}")
```

## Reference

- [Breaking Combined Multiple Recursive Generators](http://www.secmem.org/blog/2021/10/24/Breaking-Combined-Multiple-Recursive-Generators/): pbctf 2021 - Yet Another PRNGの解説
- [Attacks on Pseudo Random Number Generators Hiding a Linear Structure](https://eprint.iacr.org/2021/1204): ↑で取り上げられていた論文、本記事はこれをベースにして格子の使い方をやや変えている
