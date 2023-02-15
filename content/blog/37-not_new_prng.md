+++
title = "SECCON CTF 2022 Final - not new PRNG"
date = 2023-02-15

[taxonomies]
tags = ["CTF", "Crypto", "PRNG", "Lattice", "enumeration"]
+++

先日開催されたSECCON CTF 2022 Finalでnot new PRNGという問題を出したのでその解説をします。

<!-- more -->

## 問題概要

次のようなスクリプトとその実行結果が与えられます。

```python
import os
import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.number import getPrime


p = getPrime(128)

xs = [random.randint(1, 2**64) for _ in range(4)]

a = random.randint(1, p)
b = random.randint(1, p)
c = random.randint(1, p)
d = random.randint(1, p)
e = random.randint(1, p)  # unknown

xs.append((a*xs[-4] + b*xs[-3] + c*xs[-2] + d*xs[-1] + e) % p)
xs.append((a*xs[-4] + b*xs[-3] + c*xs[-2] + d*xs[-1] + e) % p)
xs.append((a*xs[-4] + b*xs[-3] + c*xs[-2] + d*xs[-1] + e) % p)

outs = xs[-3:]


# encryption
FLAG = os.getenv("FLAG", "fake{the_flag_is_a_lie}")
key = 0
for x in xs[:4]:
    key <<= 64
    key += x
key = int(key).to_bytes(32, "little")
iv = get_random_bytes(16)  # public
cipher = AES.new(key, AES.MODE_CBC, iv)
ct = cipher.encrypt(pad(FLAG.encode(), 16))  # public

# output
print(f"p = {p}")
print(f"a = {a}")
print(f"b = {b}")
print(f"c = {c}")
print(f"d = {d}")
print(f"outs = {outs}")
print(f"iv = 0x{iv.hex()}")
print(f"ct = 0x{ct.hex()}")
```

$x_i \equiv ax_{i-4} + bx_{i-3} + cx_{i-2} + dx_{i-1} + e \mod p$というような更新式を持つ線形合同法に似た乱数生成器に対して、最初の4つのシード値$x_0, x_1, x_2, x_3$と切片$e$が未知の状態で3つだけ出力が与えられます。但し、最初の4つのシード値はいずれも64bitの値なのに対して、法$p$が128bitであることから、他の値に比べて有意に小さくなっています。この状況で「初期のシード値を復元できるか?」というのがこの問題の本質です[^1]

## Writeup

$x_4$は$x_0, x_1, x_2, x_3$の式で表すことが出来て、$x_5$は$x_1, x_2, x_3, x_4$の式で表す事が出来ることから、$x_5$の式に$x_4$を代入することで$x_5$も$x_0,x_1,x_2,x_3$の式で表すことが出来ます。同様にして$x_6$も$x_0, x_1, x_2, x_3$の式で表すことが出来ます。具体的に$x_5$について書いてみると次のようになります。

$$
\begin{aligned}
x_5 &\equiv ax_1 + bx_2 + cx_3 + d(ax_0 + bx_1 + cx_2 + dx_3 + e) + e\mod p \cr
&\equiv adx_0 + (a + bd)x_1 + (b + cd)x_2 + (c + d^2)x_3 + (d+1)e \mod p
\end{aligned}
$$

こんな感じで未知数が$x_0, x_1, x_2, x_3,e$の合同方程式が3つ立ちますが、式同士をいい感じに足し引きすると$e$を消去した式が幾つか[^2]得られます。例えば上記の$x_5$に関する式から$x_4 \equiv ax_0 + bx_1 + cx_2 + dx_3 + e \mod p$を$d+1$倍して引けば$e$は消去出来ます。これによって、係数を気合で計算してあげると$y_i \equiv a_{i,0}x_0 + b_{i,1}x_1 + c_{i,2}x_2 + d_{i,3}x_3 \mod p$という方程式が$i=4,5,6$に対して3つ得られます。ここで、$y_i$は$x_4,x_5,x_6,a,b,c,d$から求められる数なので既知です。

あとはこの線型連立合同方程式の小さい解を見つけるだけです。人によってやり方は異なると思いますが、私は$x_0$の係数$a_{i,0}$の逆元を掛けて移項することで、$x_0 \equiv b'\_{i,1} x_1 + c'\_{i,2} x\_2 + d'\_{i,3} x\_3 + y\_i' \mod p$のような多項式を用意し、これに対して以下のような格子を錬成して短いベクトルを探しました。

$$
\begin{pmatrix}
p & & &\cr
& p \cr
& & p \cr
b_{i,1}' & b_{i,2}' & b_{i,3}' & 1 \cr
c_{i,1}' & c_{i,2}' & c_{i,3}' & & 1 \cr
d_{i,1}' & d_{i,2}' & d_{i,3}' & & & 1 \cr
y_4' & y_5' & y_6' & & & & 2^{64} 
\end{pmatrix}
$$

この基底行列で生成される格子$L$に左から$(l_4, l_5, l_6,x_1,x_2,x_3, 1)$を掛けると、$L$の格子ベクトルとして、$(x_0, x_0, x_0, x_1, x_2, x_3, 2^{64})$が現れます。というわけで、いつものように「基底簡約」をするとこのベクトルが……おそらく出てきません。

というのも、この格子の体積が小さいことから、基底簡約で出てくる基底ベクトルのノルムも小さくなってしまい、各成分のビット数は求めたい値である64bitより小さくなってしまいます。少なくともLLLでは解けない事を確認しているので、それより更に簡約された基底を出すBKZでも解けないと思います。

そこで登場するのが一定のノルム未満の格子ベクトルを全列挙するアルゴリズム(enumerationとかENUMとか呼ばれているらしい)です。CTF的には馴染みが薄いかもしれませんが、BKZのサブルーチンとして用いられていたりと、最短ベクトル問題を解く上では非常に重要なアルゴリズムとなっています。自分で実装する必要も特に無く、Sage内で[fpylll](https://github.com/fplll/fpylll)というライブラリ(正確にはfplllというライブラリのPythonラッパー)をimport出来て、ここから使う事が出来ます。詳しい使い方はfpylllの[ドキュメント](https://github.com/fplll/fpylll/blob/master/docs/tutorial.rst)を気合で読んだり、↓のコードを気合で読んだりしてください。

これを使ってこの格子に含まれるノルムが$\sqrt 7 \times 2^{64}$未満のベクトルを全列挙します。これは現実的な時間で終わっておよそ数千個のベクトルが見つかり、その中に$x_i$が埋め込まれたベクトルが入っているはずなのでそれらに対して鍵を復元して復号を試していけばどこかでフラグが手に入る、というのが想定解です。

### ソースコード

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes


p = 234687789984662131107323206406195107369
a = 35686285754866388325178539790367732387
b = 36011211474181220344603698726947017489
c = 84664322357902232989540976252462702046
d = 154807718022294938130158404283942212610
outs = [222378874028969090293268624578715626424, 42182082074667038745014860626841402403, 217744703567906139265663577111207633608]
iv = 0xf2dd287ca870eb9908bf52c44dfd9d2b
ct = 0x236a6aca059ae29056a23f5458c644abb74640d672dba1ee049eb956e629b7afb03ae33b2b2b419c24197d33baf6d88e2f0eedfa90c06e1a2be18b2fae2270f05ce39de5e0d59bb9a442d1b3eb392658e45cf721094543b13d35df8cf9ce420c
iv = long_to_bytes(iv)
ct = long_to_bytes(ct)

# ======================== solve ========================
K = GF(p)

x0,x1,x2,x3 = [var(f"x{i}") for i in range(4)]
varxs = [x0, x1, x2, x3]
# A = var("a")
# B = var("b")
# C = var("c")
# D = var("d")
E = var("e")
A = a
B = b
C = c
D = d
x4 = A*x0 + B*x1 + C*x2 + D*x3 + E
x5 = A*x1 + B*x2 + C*x3 + D*x4 + E
x6 = A*x2 + B*x3 + C*x4 + D*x5 + E

# print(x4)
# print(x4.list(x0)[1])
# print(x4.list(x1)[1])
# print(x4.list(x2)[1])
# print(x4.list(x3)[1])
# print(x4.list(x0)[0].list(x1)[0].list(x2)[0].list(x3)[0])
# print("====================================")
# print(x5)
# print(x5.list(x0)[1])
# print(x5.list(x1)[1])
# print(x5.list(x2)[1])
# print(x5.list(x3)[1])
# print(x5.list(x0)[0].list(x1)[0].list(x2)[0].list(x3)[0])
# print("====================================")
# print(x6)
# print(x6.list(x0)[1])
# print(x6.list(x1)[1])
# print(x6.list(x2)[1])
# print(x6.list(x3)[1])
# print(x6.list(x0)[0].list(x1)[0].list(x2)[0].list(x3)[0])

# print("====================================")

o4 = outs[0]
o5 = outs[1]
o6 = outs[2]

f1 = x5 - (D+1)*x4
coeffs1 = [K(f1.coefficient(v)) for v in varxs]
y1 = (o5 - (D+1)*o4) % p
f2 = x6 - (D^2+C+D+1)*x4
coeffs2 = [K(f2.coefficient(v)) for v in varxs]
y2 = (o6 - (D^2+C+D+1)*o4) % p
f3 = x6 - x5 - (D^2+C)*x4
coeffs3 = [K(f3.coefficient(v)) for v in varxs]
y3 = (o6 - o5 - (D^2+C)*o4) % p


# y_i = sum(c_i*x for c_i, x in zip(coeff_i, xs)) mod p
# x_i < bound
def solve_isis(ys, coeffs, p, bound):
    assert len(ys) == len(coeffs)
    n = len(ys)
    m = len(coeffs[0])
    size = n+m
    L = [
        [0 for _ in range(size)] for _ in range(size)
    ]
    for i in range(n):
        L[i][i] = p

    for i in range(m-1):
        L[n+i][n+i] = 1

    L[-1][-1] = bound

    # multiply inverse of a_i (the coeffient of x_1)
    for i, (y, coeff) in enumerate(zip(ys, coeffs)):
        a_inv = coeff[0]^-1
        constant = y*a_inv 
        _coeff = [-v * a_inv for v in coeff][1:] + [constant]

        for j, x in enumerate(_coeff):
            L[j+n][i] = int(x)

    # trivial unintented check
    _L = matrix(ZZ, L)
    for b in _L.LLL():
        if abs(b[-1]) == bound and b[0] == b[1] == b[2]:
            for x in b:
                print(abs(x))


    # intented solution (enumeration)
    from fpylll import IntegerMatrix, LLL
    from fpylll.fplll.gso import MatGSO
    from fpylll.fplll.enumeration import Enumeration

    sols = []

    A = IntegerMatrix.from_matrix(L)
    LLL.reduction(A)
    M = MatGSO(A)
    M.update_gso()

    sol_cnt = 3000
    enum = Enumeration(M, sol_cnt)
    answers = enum.enumerate(0, size, (size * bound**2), 0, pruning=None)

    for _, s in answers:
        v = IntegerMatrix.from_iterable(1, A.nrows, map(int, s))
        sv = v * A

        if abs(sv[0, size-1]) == bound:
            sig = 1 if sv[0, size-1] == bound else -1
            sv = [sig*x for x in sv[0]]
            valid = True
            for x in sv:
                if x < 0:
                    valid = False
                    break
            if not valid:
                continue

            if len(set(sv[:n])) != 1:
                continue

            sols.append([sv[0]] + sv[n:-1])

    return sols

candidates = solve_isis([y1, y2, y3], [coeffs1, coeffs2, coeffs3], p, 2^64)
for v in candidates:
    key = 0
    for x in v:
        key <<= 64
        key += x
    key = int(key).to_bytes(32, "little")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    valid_flag = True
    for _c in pt:
        if _c > 0x7f:
            valid_flag = False
            break

    if valid_flag:
        print(unpad(pt, 16).decode())
        print(v)
        break

```

これを実行すると`SECCON{My_challenges_tend_to_be_solved_by_lattice_'reduction'. How_did_you_do_this_time?}`が得られます。こんなフラグですが、国内外のチームに話を聞いてみたところ、おそらく大抵のチームは気合で格子を錬成してLLL等の基底簡約で解いたように思えます。そして、そんな苦行[^3]を国際では9チーム[^4]、国内では2チームもしたことを考えるとその実装力の高さに震えます。

## 反省

実は同じ`outs`を出力するシード値$x_0, x_1, x_2, x_3$は一意に定まりません。運が悪いとLLL等で出てきたベクトルをシード値にして生成された乱数がこの問題インスタンスの`outs`と一致する事があります。これが(主に国際のプレイヤーに)評判が悪かったようです。

確かに、私もz3等で求めた充足解がフラグに全く関係ないと嫌な気持ちになりますし、この指摘はごもっともです。今回は解法ありきで問題を作った結果、割とイライラするような問題になってしまったのは否めないと思います。

---

と、いうようなフィードバックを頂いて、以後の問題作成に積極的に活かすつもりですので、(SECCONに限らず)Surveyはしっかり書くと後々良いCTFになると思います。というわけで書きましょう。

---

[^1]: 4つのシード値を復元するとAESの鍵が導かれる

[^2]: 手元では3つ用意した

[^3]: 私にとっては苦行なのだが、国際チームではhellのフラグを出してから30分で解いていたチームもいたので苦行ではないのかもしれない

[^4]: 国際チームは最終的に10チーム参加していたのでほとんどのチームが解けていたということになる
