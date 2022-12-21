+++
title = "ペアリングでCTFの問題を解く"
date = 2022-12-22

[taxonomies]
tags = ["CTF", "Crypto", "Pairing", "Elliptic_Curve"]
+++

この記事は[CTF Advent Calendar 2022 - Adventar](https://adventar.org/calendars/7550)の12/22[^1]分の記事です。昨日は[れっくす](https://twitter.com/xrekkusu)さんの[CTFプレイヤーにアンケート取ってなんかやりたくない？（結果編） - rex-gs](https://rex.gs/2022/12/ctf%E3%83%97%E3%83%AC%E3%82%A4%E3%83%A4%E3%83%BC%E3%81%AB%E3%82%A2%E3%83%B3%E3%82%B1%E3%83%BC%E3%83%88%E5%8F%96%E3%81%A3%E3%81%A6%E3%81%AA%E3%82%93%E3%81%8B%E3%82%84%E3%82%8A%E3%81%9F%E3%81%8F%E3%81%AA%E3%81%84%E7%B5%90%E6%9E%9C%E7%B7%A8/)でした。標本がCTFプレイヤーに偏っているとは言え、興味深い結果だと思いつつ楽しく読んでいたら、最後にバトンパスされて自分が担当なことを思い出しました。リマインドありがとうございます。

<!-- more -->

## 序文

この記事は、先日行われたzer0pts主催のyoshi-campで私が発表した内容を元に書いています。実際は他の講師が「猫に関連する粋なタイトル」を付けていたのでそれに準じて猫とペアリングに関連するタイトルを付けていたのですが、非常に分かり辛いタイトルを付けたせいでネタに気付かれず滑り倒したので、本記事は「ペアリングでCTFの問題を解く」という至ってシンプルなタイトルとしています[^2]。

内容としては、はじめに楕円曲線のペアリングの性質をざっくり説明してから、それを利用してCTFの問題を解くという形にしました。本記事もそれに従う構成となっています。

## Prerequisite

- ECDLP
- 体論 (有限体$\mathbb F_p$の拡大体$\mathbb F_{p^k}$が登場する程度です)

## 双線型写像

体$K$とその上の楕円曲線$E$に対して、次のような性質を持つ2変数関数$f: E/K \times E/K \to \overline K$を考えます($\overline K$は$K$の代数閉包)。

1. $f(P_1 + P_2, Q) = f(P_1, Q)f(P_2, Q)$
2. $f(P, Q_1 + Q_2) = f(P, Q_1)f(P, Q_2)$

この性質(双線形性)を用いると、点のスカラー倍に関して次の性質が成り立ちます。

1. $f(aP, Q) = f(P,Q)^a$
2. $f(P, bQ) = f(P, Q)^b$

もし、こういう$f$が存在する場合、次のような問題(DDH問題)を解く事が出来ます。

「$E/K$上の点$P$とそのスカラー倍(何倍したかは未知)した2つの点$aP, bP$が既知の時に、$abP$か、$c \neq ab$である$c$を用いて$cP$のいずれかを与えられて、どちらが与えられたかを当てる。」

関数$f$に$aP, bP$を入れると双線形性から$f(aP, bP) = f(P, bP)^a = f(P, P)^{ab}$が成り立ちます。また、$P, abP$を入れると$f(P, abP) = f(P, P)^{ab}$が成り立ちます。よって、この2つの結果から$f(aP, bP) = f(P, abP)$が成り立つことがわかります。

一方で、もしこれが$P, abP$でなく、$P, cP$を入れた場合は$f(P, cP) = f(P, P)^c$となって、一般的にこれは$f(aP, bP) = f(P, P)^{ab}$とは等しくなりません。したがって、与えられた点を$xP$とおくと、$f(aP, bP) = f(P, xP)$が成り立つかどうかでこの判別問題を解く事が出来ます。

さて、ここまではこのような便利な性質を持つ関数$f$が存在するという仮定を敷いていましたが、本当に存在するのでしょうか? 嬉しい事にこれは存在して、しかもCryptoプレイヤーなら皆大好きなSageMathに実装があり、点`P`に対して`P.weil_pairing(Q)`や`P.tate_pairing(Q)`等で使えます。

`tate_pairing()`の方は埋め込み次数というものを指定したりと、何も考えずに使えるわけではありませんが、[Points on elliptic curves - Elliptic curves](https://doc.sagemath.org/html/en/reference/arithmetic_curves/sage/schemes/elliptic_curves/ell_point.html)辺りを見ればなんとなくわかると思います。

```python
# these parameters will reappear later
q = 0x3a05ce0b044dade60c9a52fb6a3035fc9117b307ca21ae1b6577fef7acd651c1f1c9c06a644fd82955694af6cd4e88f540010f2e8fdf037c769135dbe29bf16a154b62e614bb441f318a82ccd1e493ffa565e5ffd5a708251a50d145f3159a5
a, b = 1, 0
o = 21992493417575896428286087521674334179336251497851906051131955410904158485314789427947788692030188502157019527331790513011401920585195969087140918256569620608732530453375717414098148438918130733211117668960801178110820764957628836  # order of Elliptic Curve
r = 2344807743588794553832391292516279194397209456764712786969868894104465782493871625440983981162219279755855675661203
k = 2  # embedding degree
assert (q^k - 1) % r == 0

assert o == 2**2 * r**2

K = GF(q)
E = EllipticCurve(K, [a, b])  # E = <G1, G2>

# orders of point may be r or 2*r
P = E.random_point()
o_P = P.order()

if o_P != r:
    P *= 2
    o_P //= 2

Q = E.random_point()
o_Q = Q.order()

if o_Q != r:
    Q *= 2
    o_Q //= 2


# calculate e(P, Q)
wp_PQ = P.weil_pairing(Q, r)

a = randint(1, r)
b = randint(1, r)

# calculate e(aP, bQ)
wp_aPbQ = (a*P).weil_pairing(b*Q, r)

assert wp_aPbQ == wp_PQ^(a*b)

# calculate e(P, aP) (by `weil_pairing`)
wp_PaP = P.weil_pairing(a*P, r)
assert wp_PaP == 1

# calculate e(P, aP) (by `tate_pairing`)
tp_PaP = P.tate_pairing(a*P, r, 2)
assert tp_PaP != 1

# solve DDH Problem
aP = a*P
bP = b*P
abP = (a*b)*P
c = randint(1, 10**6)
cP = c*P

xP = choice([abP, cP])

# write your own code
tp_aPbP = aP.tate_pairing(bP, r, 2)
tp_PxP = P.tate_pairing(xP, r, 2)

select_P = abP if tp_aPbP == tp_PxP else cP
assert select_P == xP
```

但し、どんな曲線でもこのような性質を利用出来るのかというとそうではなく、詳しくは脱線が過ぎたりそもそも私がよく理解していない[^3]ので省きますが、だいたいの曲線はペアリングの性質を上手く利用する事が出来ません。そういうわけでペアリングが上手く使えるような曲線のことを"Pairing Friendly Curve"と呼んだりします。

## Circle City Con 2021 - Random is Also Valid

この問題の紹介に入る前に1つだけ解説しなくてはならない概念があって、それがBLS12-381曲線です。この曲線は$\mathbb F_{q^{12}}$上で定義された曲線でペアリングが出来ます。しかし、$\mathbb F_{p^{12}}$の要素の計算は非常に重いため、実用するためにはここを多少工夫する必要があります。

この曲線はBLS署名[^4]という署名のために用意されており、BLS署名では点のスカラー倍がよく登場します。そこで、署名で使う生成元を線形独立に2つ用意してそれが生成する$E/\mathbb F_{q^{12}}$上の部分群を、比較的計算が簡単な楕円曲線上の同型な部分群へ移す事が出来れば良さそうです。

そういうわけでBLS12-381には次の3つの曲線が登場します

$$
\begin{aligned}
E/\mathbb F_q&: x^3 + 4 \cr
E'/\mathbb F_{q^2}&: x^3 + 4(1+i) \cr
E/\mathbb F_{q^{12}}&: x^3 + 4
\end{aligned}
$$

1つ目の曲線は曲線の形は同じで単に$\mathbb F_q$がベースの体となっているだけです。$\mathbb F_q$の要素同士の演算は$\mathbb F_{q^{12}}$上でも特に変わらない上に$\mathbb F_q$内で保存されるため、楕円曲線上の点に関しても同様の事が成り立ちます。よって、$E/\mathbb F_{q^{12}}$上の点で要素が$\mathbb F_q$の成分からなる点は特になんの捻りも無く$E/\mathbb F_q$と対応させることが出来ます。

2つ目の曲線は$\mathbb F_q$における$-1$の平方根$i$を用いています。この元は$\mathbb F_q$内には存在しないため、$\mathbb F_{q^2} = \mathbb F_q[x]/(x^2 +1)$という拡大で作られています。この曲線と$E/\mathbb F_{q^{12}}$(のある部分群)は次のような対応をします。

$$
\begin{aligned}
E'/\mathbb F_{q^2} &\to E/\mathbb F_{q^{12}} \cr
(x,y) &\mapsto (z^2x, z^3y)
\end{aligned}
$$

ここで、$z$は$z^6 = (1+i)^{-1}$を満たす$\mathbb F_{q^{12}}$の元です。この変換を6次ツイストと言います。

以上でようやく問題の準備が整いました。問題は次のスクリプトとその実行結果からなっています。

```python
import sys, json
from collections import namedtuple
from Crypto.Random.random import randrange

q = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
r = int(0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001)

F = GF(q, x, x)
F2.<x> = GF(q^2, x, x^2 + 1)

def down(t, x):
    return t(x.polynomial().mod(t.modulus()))

class Point(namedtuple("_Point", "x y")):
    def __init__(self, *args, **kw):
        assert self.is_valid()

    def is_valid(self):
        return self.is_inf() or self.x ^ 3 + down(self.x.parent(), 4*x + 4) == self.y ^ 2

    @property
    def inf(self):
        return type(self)(self.x.parent()(0), self.y.parent()(0))

    def is_inf(self):
        return self.x == self.y == 0

    def __add__(self, o):
        if self.is_inf():
            return o
        elif o.is_inf():
            return self
        if self != o and self.x == o.x:
            return self.inf
        if self == o:
            l = (3*(self.x^2))/(2*self.y)
        else:
            l = (self.y - o.y)/(self.x - o.x)
        nx = l^2 - self.x - o.x
        ny = l*(self.x - nx) - self.y
        return Point(nx, ny)

    def __neg__(self):
        return Point(self.x, -self.y)

    def __mul__(self, scalar):
        if scalar < 0:
            self = -self
            scalar = -scalar
        res = self.inf
        while scalar:
            if scalar & 1:
                res = res + self
            self = self + self
            scalar >>= 1
        return res

G1 = Point(F(4), F(0x0a989badd40d6212b33cffc3f3763e9bc760f988c9926b26da9dd85e928483446346b8ed00e1de5d5ea93e354abe706c)) * 0x396c8c005555e1568c00aaab0000aaab
G2 = Point(F2(2), F2(0x013a59858b6809fca4d9a3b6539246a70051a3c88899964a42bc9a69cf9acdd9dd387cfa9086b894185b9a46a402be73 + 0x02d27e0ec3356299a346a09ad7dc4ef68a483c3aed53f9139d2f929a3eecebf72082e5e58c6da24ee32e03040c406d4f*x)) * 0x5d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa628f1cb4d9e82ef21537e293a6691ae1616ec6e786f0c70cf1c38e31c7238e5

def format_v(v):
    return [hex(c) for c in v.polynomial().coefficients()]

def format_pt(P, name):
    return {f"{name}_x": format_v(P.x), f"{name}_y": format_v(P.y)}

def format_output(P_A, P_B, P_C):
    return {**format_pt(P_A, "P_A"), **format_pt(P_B, "P_B"), **format_pt(P_C, "P_C")}

def exchange_real():
    a = randrange(r)
    P_A = G1 * a
    b = randrange(r)
    P_B = G2 * b
    P_C = [P_B * a, P_A * b][randrange(int(2))]
    return format_output(P_A, P_B, P_C)

def exchange_fake():
    a = randrange(r)
    P_A = G1 * a
    b = randrange(r)
    P_B = G2 * b
    c = randrange(r)
    P_C = [G1, G2][randrange(int(2))] * c
    return format_output(P_A, P_B, P_C)

if __name__ == "__main__":
    with open(sys.argv[1], "rb") as f:
        flag = f.read()
    res = []
    for byte in flag:
        for bit in map(int, bin(byte)[2:].zfill(8)):
            if bit:
                res.append(exchange_real())
            else:
                res.append(exchange_fake())
    with open("out.txt", "w") as f:
        json.dump(res, f)
```

コード自体は長いですが本質は簡単で、BLS12-381曲線でDDH問題を解くだけとなっています。

$G_1 \in E/\mathbb F_q$と$G_2 \in E'/\mathbb F_{q^2}$に関して、フラグを1bitずつ見ていった時に1なら$aG_1, bG_2, abG_1$が与えられて($abG_1$の代わりに$abG_2$が与えられることもある)、0ならランダムに選ばれた整数$c$にを用いて$aG_1, bG_2, cG_1$が与えられます($cG_1$の代わりに$cG_2$のこともある)。よって、何らかのペアリング関数$f$を用いて$f(aG_1, bG_2) = f(G_1, cG_1)$が成り立つかそうでないかを見るだけなのですが、$G_1, G_2$はこれらを含む楕円曲線が異なるので$E/\mathbb F_{q^{12}}$へ戻してあげる必要があります。

というわけで6次ツイストを実装するのですが、これが非本質的要素の癖にめちゃくちゃ面倒で、本質であるDDH問題を解くことの方が簡単です(そういう意味ではyoshi-campで扱ったのは失敗だと思っています)。

最初の障害が$\mathbb F_{q^{12}}$を定義するところです。BLS12-381の詳細については、[BLS12-381 For The Rest Of Us - HackMD](https://hackmd.io/@benjaminion/bls12-381)を参考にしたのですが、これによればこの拡大体は次のような多段の拡大によって定義されています[^5]。

$$
\begin{aligned}
\mathbb F_{q^2} &= \mathbb F_q[u]/(u^2+1) \cr
\mathbb F_{q^6} &= \mathbb F_q^2[v]/(v^3-(u+1)) \cr
\mathbb F_{q^{12}} &= \mathbb F_q^6[w]/(w^2 - v)
\end{aligned}
$$

この拡大を愚直にやろうとしても上手くいかなかったので、法となる多項式を直接求めてそれを引数に叩き込むという強引な方法をとります。

まず一番下の式より、$w^2 - v = 0$を満たすので、移項して両辺3乗すると$w^6 = v^3$が成り立ちます。続いて真ん中の式より、$v^3 = u+1$が成り立つので$w^6 = u+1$が成り立ちます。ここで、一番上の式から$u^2+1 = 0$が成り立つので、$u$だけ残すように移項して2乗すると次が成り立ちます。

$$
w^{12} - 2w^6 + 2 = 0
$$

したがって、添加する元$w$は$w^{12} - 2w^6 + 2 = 0$を満たすので、$\mathbb F_{q^{12}} = \mathbb F_q[x] / (x^{12} - 2x^6 + 2)$として作る事が出来ます。SageMathでは次数と多項式を指定すると有限体を定義出来るので`F12.<w> = GF(q**12, "w", x**12 - 2*x**6 + 2)`として$\mathbb F_{q^{12}}$を作る事が出来ます。

次の障害は$E'/\mathbb F_{q^2}$の点を6次ツイストで$E/\mathbb F_{q^{12}}$に移す際に$i$をどう扱うかです。BLS12-381で用いる$E'/\mathbb F_{q^2}$の点はx,y座標共に$i$を含む$\mathbb F_{q^2}$の要素ですが、これをSageMathで扱おう際に$\mathbb F_{q^2}$の要素である$i$をそのまま$\mathbb F_{q^{12}}$の要素にキャストしようとしても(少なくとも私が雑に試した限りでは)上手くいきません。面倒ですが、$w$はSageMathで上手く扱えるので、$i$を$w$の要素として扱う事を考えます。

これは比較的簡単で、先程の式から$w^6 = u+1$を満たし、(記号を濫用していて申し訳ないですが)$u$は$i$と同じなので$i = w^6 - 1$となります。

最後に6次ツイストで使う$z$をどう表すかですが、$z = \left(\frac{1}{1+i}\right)^{\frac 16}$を信じて`nth_root()`等で6乗根を取ろうとしても上手くいきませんでした。というわけで$i$と同様に$w$で表す事を考えます。

$w^6 = 1+i$が成り立っているので、両辺逆数をとると$\frac 1{w^6} = \frac 1{1+i}$となり、ここから$z = \frac 1w$とすれば$z$の要件を満たす事になります。

以上より、最終的なソルバは次のようになります。

```python
import json


q = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

F = GF(q, x, x)
F2.<i> = GF(q^2, "i", x^2 + 1)
F12.<w> = GF(q**12, "w", x**12 - 2*x**6 + 2)

i12 = w**6 - 1
z = w^-1

E1 = EllipticCurve(F, [0, 4])
E2 = EllipticCurve(F2, [0, 4*(1+i)])
E12 = EllipticCurve(F12, [0, 4])


def F2_to_F12(coeffs):
    assert len(coeffs) == 2
    c = coeffs[0]
    d = coeffs[1]
    x = c + d*i12

    return x


def sextic_twist(Px, Py):
    x = F2_to_F12(Px)
    y = F2_to_F12(Py)

    return E12(z^2*x, z^3*y)

G1 = E12(F(4), F(0x0a989badd40d6212b33cffc3f3763e9bc760f988c9926b26da9dd85e928483446346b8ed00e1de5d5ea93e354abe706c)) * 0x396c8c005555e1568c00aaab0000aaab
G2 = E12(z^2*2, z^3*(0x013a59858b6809fca4d9a3b6539246a70051a3c88899964a42bc9a69cf9acdd9dd387cfa9086b894185b9a46a402be73 + 0x02d27e0ec3356299a346a09ad7dc4ef68a483c3aed53f9139d2f929a3eecebf72082e5e58c6da24ee32e03040c406d4f*i12)) * 0x5d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa628f1cb4d9e82ef21537e293a6691ae1616ec6e786f0c70cf1c38e31c7238e5

with open("out.txt") as f:
    out_list = json.load(f)

flag_bits = ""
for out in out_list:
    PAx = int(out["P_A_x"][0], 16)
    PAy = int(out["P_A_y"][0], 16)
    PA = E12(PAx, PAy)
    _int = lambda x: int(x, 16)
    PBx = list(map(_int, out["P_B_x"]))
    PBy = list(map(_int, out["P_B_y"]))
    PB = sextic_twist(PBx, PBy)
    use_F2 = len(out["P_C_x"]) == 2
    e_aGbG = PA.weil_pairing(PB, r)
    if use_F2:
        PCx = list(map(_int, out["P_C_x"]))
        PCy = list(map(_int, out["P_C_y"]))
        PC = sextic_twist(PCx, PCy)
        res = G1.weil_pairing(PC, r)
    else:
        PCx = int(out["P_C_x"][0], 16)
        PCy = int(out["P_C_y"][0], 16)
        PC = E12(PCx, PCy)
        res = PC.weil_pairing(G2, r)

    flag_bits += "1" if res == e_aGbG else "0"

    if len(flag_bits) % 8 == 0:
        flag = int.to_bytes(int(flag_bits, 2), len(flag_bits) // 8, "big")
        print(flag)

```

## hxpCTF 2021 - zipfel

実際のhxpCTF 2021では、"gipfel"と"kipferl"という2つの問題が存在してそれに続く最終問題となるのがこのzipfelでした。問題で使われているプロトコルはだいたい同じで、前問の想定解を潰すような設計になっているので[問題サイト](https://2021.ctf.link/internal/)から問題を回収してから挑むと理解しやすいかもしれません(つまりこの2つの問題の解説はしません[^6])。

次のようなスクリプトが与えられます

```python
#!/usr/bin/env python3
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import signal, random
random = random.SystemRandom()

q = 0x3a05ce0b044dade60c9a52fb6a3035fc9117b307ca21ae1b6577fef7acd651c1f1c9c06a644fd82955694af6cd4e88f540010f2e8fdf037c769135dbe29bf16a154b62e614bb441f318a82ccd1e493ffa565e5ffd5a708251a50d145f3159a5
a, b = 1, 0

################################################################

# https://www.hyperelliptic.org/EFD/g1p/data/shortw/xz/ladder/ladd-2002-it
def xDBLADD(P,Q,PQ):
    (X1,Z1), (X2,Z2), (X3,Z3) = PQ, P, Q
    X4 = (X2**2-a*Z2**2)**2-8*b*X2*Z2**3
    Z4 = 4*(X2*Z2*(X2**2+a*Z2**2)+b*Z2**4)
    X5 = Z1*((X2*X3-a*Z2*Z3)**2-4*b*Z2*Z3*(X2*Z3+X3*Z2))
    Z5 = X1*(X2*Z3-X3*Z2)**2
    X4,Z4,X5,Z5 = (c%q for c in (X4,Z4,X5,Z5))
    return (X4,Z4), (X5,Z5)

def xMUL(P, k):
    Q,R = (1,0), P
    for i in reversed(range(k.bit_length()+1)):
        if k >> i & 1: R,Q = Q,R
        Q,R = xDBLADD(Q,R,P)
        if k >> i & 1: R,Q = Q,R
    return Q

################################################################

def enc(a):
    f = {str: str.encode, int: int.__str__}.get(type(a))
    return enc(f(a)) if f else a

def H(*args):
    data = b'\0'.join(map(enc, args))
    return SHA256.new(data).digest()

def F(h, x):
    r = xMUL((h,1), x)
    return r[0] * pow(r[1],-1,q) % q

################################################################

password = random.randrange(10**6)

def go():
    g = int(H(password).hex(), 16)

    privA = 40*random.randrange(2**999)
    pubA = F(g, privA)
    print(f'{pubA = :#x}')

    pubB = int(input(),0)
    if not 1 < pubB < q:
        exit('nope')

    shared = F(pubB, privA)

    verB = int(input(),0)
    if verB == F(g, shared**5):
        key = H(password, shared)
        flag = open('flag.txt').read().strip()
        aes = AES.new(key, AES.MODE_CTR, nonce=b'')
        print(f'flag:', aes.encrypt(flag.encode()).hex())
    else:
        print(f'nope! {shared:#x}')

# three shots, three opportunities
# to seize everything you ever wanted
# would you capture? or just let it slip?
signal.alarm(2021)
go()
go()
go()


```

何やら楕円曲線上の点のスカラー倍(コード中の関数`F`)において謎アルゴリズム(x座標だけが計算される)が使われていますが、スカラー倍した結果が無限遠点とならなければ特に問題はありません。ちなみに無限遠点になってしまう場合は`return r[0] * pow(r[1],-1,q) % q`のところで`ZeroDivisionError`を吐かれます。

$y^2 = x^3 + x$という曲線(実はこの曲線は埋め込み次数が小さいのでペアリングが上手くいく)の上で次のようなプロトコルが走っています。

公開されませんが、総当り可能($10^6$通り)な点$G$を生成元とし、非公開の$a \in \mathbb Z$を用いて$aG$が与えられます。それに対してこちらから何らかの点$B$を送ります。ここで注意しなくてはならないのは$G$は未知なので、必ずしも$B = bG$となる、つまり$B \in \langle G \rangle$となるような点$B$を送る事が出来るわけではないということです。

このような$B$に対してサーバーは$aB$を計算し、その$x$座標を$s$(`shared`)として、$s^5G$を当てる事が出来るかどうかを要求します。もし、出来れば$s$と`password`(これは実質$G$)の両方を知っていれば復号出来るような暗号文を渡され、そうでなければ$s$が開示されるのみです。

以上のプロトコルを最大3回まで行う事が出来て、更に$G$はセッションを通して使い回されています。この使い回しと`shared`が開示されるという事を利用してこの問題を解きます。

1回目の`go()`において適当な点$B$を送ったとします。この時、`shared`に対応する点を$S$とおくと、$S = aB$が成り立ちます。ここで、何らかのペアリング$e$を用いて$e(aG, B)$を計算してみると次のようになります。

$$
e(aG, B) = e(G, aB) = e(G, S)
$$

ここで、$G$は以降の`go()`でも使われる上に総当り可能です。$aG, B, S$は`go()`の最後で全て既知になることから、$G$を総当りしながら上の式が成り立つような$G$を探せば$G$を特定することが出来ます。

さて、勘の良い皆さんなら既にお気付きかもしれませんが、このプロトコルは$G$が判明していれば簡単にフラグを手に入れる事が出来ます。$B$を送る際に何らかの整数$b$を用意して$B = bG$としてしまえば、ECDHの要領で`shared`が既知となるからです。$G$も既知なのでそこから`password`も簡単な総当りで判明します。

以上をまとめると次のようなコードになります

……と、言いたかったのですが、この問題は`alarm(2021)`で30分程度しか通信できない上、手元のマシンだと`weil_pairing()`も`tate_pairing()`も非常に遅く、30分以内で30000回程度しかペアリング計算が出来ませんでした。[作問者Writeup](https://hxp.io/blog/91/hxp-CTF-2021-gipfelkipferlzipfel-writeup/)によれば

> My own implementation of the (Tate) pairing solves the challenge within a single connection on a 4-core laptop.

という信じられない事が書かれていたのでもしかするとどこかで見落としがあるかもしれないです。

結局、yoshi-campでこれを扱うために、限られた演習時間を節約するために$G$のエントロピーを$10^4$としました[^7]。以下はその場合のソルバとなっています。

```python
from pwn import process
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from tqdm import tqdm

q = 0x3a05ce0b044dade60c9a52fb6a3035fc9117b307ca21ae1b6577fef7acd651c1f1c9c06a644fd82955694af6cd4e88f540010f2e8fdf037c769135dbe29bf16a154b62e614bb441f318a82ccd1e493ffa565e5ffd5a708251a50d145f3159a5
K = GF(q)
a, b = 1, 0
E = EllipticCurve(K, [a, b])

# from sagemath
r = 2344807743588794553832391292516279194397209456764712786969868894104465782493871625440983981162219279755855675661203
o = 21992493417575896428286087521674334179336251497851906051131955410904158485314789427947788692030188502157019527331790513011401920585195969087140918256569620608732530453375717414098148438918130733211117668960801178110820764957628836  # order of E

################################################################

# https://www.hyperelliptic.org/EFD/g1p/data/shortw/xz/ladder/ladd-2002-it
def xDBLADD(P,Q,PQ):
    (X1,Z1), (X2,Z2), (X3,Z3) = PQ, P, Q
    X4 = (X2**2-a*Z2**2)**2-8*b*X2*Z2**3
    Z4 = 4*(X2*Z2*(X2**2+a*Z2**2)+b*Z2**4)
    X5 = Z1*((X2*X3-a*Z2*Z3)**2-4*b*Z2*Z3*(X2*Z3+X3*Z2))
    Z5 = X1*(X2*Z3-X3*Z2)**2
    X4,Z4,X5,Z5 = (c%q for c in (X4,Z4,X5,Z5))
    return (X4,Z4), (X5,Z5)

def xMUL(P, k):
    Q,R = (1,0), P
    for i in reversed(range(k.bit_length()+1)):
        if k >> i & 1: R,Q = Q,R
        Q,R = xDBLADD(Q,R,P)
        if k >> i & 1: R,Q = Q,R
    return Q

################################################################

def enc(a):
    f = {str: str.encode, int: int.__str__}.get(type(a))
    return enc(f(a)) if f else a

def H(*args):
    data = b'\0'.join(map(enc, args))
    return SHA256.new(data).digest()

# calculate x-coordinate of (x * (h, y)) (y = E.lift(x))
def F(h, x):
    r = xMUL((h,1), x)
    return r[0] * pow(r[1],-1,q) % q

################################################################

print("[+] Start Exploit")

pubB = E.random_point()

sc = process(["python", "vuln_easy.py"])

sc.recvuntil(b"pubA = ")
pubA = int(sc.recvline(), 16)
if not K(pubA**3 + a*pubA).is_square():
    print("[+] unko")
    exit()
pubA = E.lift_x(Integer(pubA))

sc.sendline(str(pubB.xy()[0]).encode())

sc.sendline(str(114514).encode())
sc.recvuntil(b"nope!")
shared = int(sc.recvline(), 16)
S = E.lift_x(Integer(shared))

G = None
for i in tqdm(range(10**4)):
    estimate_gx = int(H(i).hex(), 16)
    if not K(estimate_gx**3 + a*estimate_gx).is_square():
        continue

    estimate_G = E.lift_x(Integer(estimate_gx))
    pairing1 = pubB.tate_pairing(pubA, 2*r, 1)
    pairing2 = S.tate_pairing(estimate_G, 2*r, 1)

    if pairing1 == pairing2:
        G = estimate_G
        break

assert G is not None
print("[+] Found")
print(estimate_G)

pubB = 114514 * G

sc.recvuntil(b"pubA = ")
pubA = int(sc.recvline(), 16)
pubA = E.lift_x(Integer(pubA))

sc.sendline(str(pubB.xy()[0]).encode())

shared = int((114514*pubA).xy()[0])
verB = ((shared**5) * G).xy()[0]
sc.sendline(str(verB).encode())

sc.recvuntil(b"flag:")

print("[+] Start Brute Force")
password = None
for i in range(10**6):
    estimate_g = int(H(i).hex(), 16)
    if estimate_g == int(G.xy()[0]):
        print("[+] Found!!")
        print(i)
        password = i
        break

assert password is not None
g = int(H(i).hex(), 16)

ct_hex = sc.recvline().strip()
ct = bytes.fromhex(ct_hex.decode())

key = H(password, shared)
aes = AES.new(key, AES.MODE_CTR, nonce=b"")
print(aes.decrypt(ct))
```

なお、楕円曲線の計算はx座標だけで行われていますが、この問題のアルゴリズムは$x^3 + x$が$\mathbb F_q$上で平方剰余では無いものもx座標として計算出来る($E/\mathbb F_{q^2}$上での計算をしているらしい?)ようなので、もし`password`がそのようなものだった場合は再接続する必要があります。hxp CTF 2021の最中は、kipferlで凡ミスしてzipfelに辿り着かなかったため関係ないですが、PoW付きの問題としてはかなり厳しい問題だと思いました。

## 結び

CTF Advent Calendar 2022の明日の担当は[チョコラスク](https://twitter.com/nuo_chocorusk)さんで「変な方法で解いたcrypto問のwriteup2つ予定」だそうです。今年に入ってからCryptoの問題を異常な勢いで解いている姿をよく見るので非常に楽しみです。

また、アドカレ自体はまだ最終日だけ空いているので、殿(しんがり)を務めたいというそこの貴方の記事をお待ちしております。

---

[^1]: 昨年もこの日付を取っていて実はこの日付には拘りがあるのですが、その理由は皆様のご想像におまかせします

[^2]: 発表タイトルが気になる人は他の参加者にこっそり聞くか、そのうち公開されるかもしれない参加記でご確認ください

[^3]: (ここまでで全く触れてこなかった言葉が飛び出して申し訳ないが) 線形独立で位数が同じ部分群が存在する拡大体を構成するための拡大次数(埋め込み次数ともいうらしい)がデカすぎる、のような理解をしている

[^4]: BLS署名のBLSとBLS12-381のBLSはどちらも人名の頭文字から来ているが、実は両者におけるこれらは(L以外は)異なっている (前者がBoneh, Lynn, Shachamに対して後者はBarreto, Lynn, Scott)

[^5]: 文献に従ってこのようにしているだけで、実はこのように定義せず、どんな既約多項式で割っても上手くいくらしい

[^6]: yoshi-campではスッカスカのスライドを埋める事の方が重要だったので解説した

[^7]: なお、Random is Also Validの非本質パートで長引きすぎた上に、俺の講師役としての不手際が目立ちまくってzipfelは復習回送りになった(すいません)
