+++
title = "redpwnCTF 2020 - speedy-signature"
date = 2020-12-01

[taxonomies]
tags = ["CTF", "Writeup", "Crypto", "Elliptic Curve"]
+++

今年の6月に開催されたredpwnCTFで触りもしなかったCrypto問題であるspeedy-signatureを解いたのでそのWriteupになります。

<!-- more -->

## Writeup

### Outline

楕円曲線DSAの問題で100回行われる署名手順で使われている秘密鍵を導出すればフラグが開示される。

セッションを通して固定な`k`にランダムな4096未満の自然数を加えた`k1, k2`を署名に使う。1回の署名で2つの署名がそれぞれ生成されるが、`(r, s)`の組がシャッフルされる上に1つ削除された状態で渡される。

この3つの数字からまず署名として正しい組を選んで抽出する。1回目の署名で残りの数字が`s`である場合を引くまで試し、その場合における`r`を`k1, k2`の差が小さいという情報を元に点の加減算の総当りを繰り返して復元する。

この際、`r`と同時に`k1, k2`の差も判明するのでこれらの情報から秘密鍵を復元できる。

以降の署名では、初回の`k`の片割れが判明していることからこの±4096の範囲で点の加減算を行い、そのx座標を辞書のキー, `k`を値として格納しておくことで与えられた`r`から`k`を導出出来る。

`k`が判明すれば秘密鍵も特定出来るので残り99回はそれをする。

### 配布ソースコード

```python
#!/usr/bin/env python3

from Crypto.Util.number import inverse
import ecdsa
import random
import hashlib

flag = open('flag.txt','rb').read()

C = ecdsa.NIST256p
G = C.generator
n = C.order
k = random.randint(1,n-1)

for i in range(100):
    print("> ROUND ",i+1)

    ans = random.randint(1,n-1)
    Q = G*ans
    print(Q.x(),Q.y())

    m1 = input("Enter first message: ").encode()
    h1 = int(hashlib.sha256(m1).hexdigest(),16)
    done = False
    while not done:
        k1 = k+random.randint(1,4096)
        P = k1*G
        r1 = P.x()%n
        if r1 == 0:
            continue
        s1 = inverse(k1,n)*(h1+r1*ans)%n
        if s1 == 0:
            continue
        done = True

    m2 = input("Enter second message: ").encode()
    h2 = int(hashlib.sha256(m2).hexdigest(),16)
    done = False
    while not done:
        k2 = k+random.randint(1,4096)
        if k1 == k2:
            continue
        P2 = k2*G
        r2 = P2.x()%n
        if r2 == 0:
            continue
        s2 = inverse(k2,n)*(h2+r2*ans)%n
        if s2 == 0:
            continue
        done = True

    sigs = [str(r1),str(s1),str(r2),str(s2)]
    random.shuffle(sigs)
    sigs.pop(random.randint(0,3))
    print(' '.join(sigs))

    user_ans = int(input("What's my number?\n").strip())
    if user_ans == ans:
        print("Correct!")
        if i == 99:
            print("Here's your flag: {}".format(flag))
    else:
        print("Wrong! Better luck next time...")
        break
    print()
```

`NIST256p`で使われている曲線のパラメータは次のようにして判明する。

```python
>>> from ecdsa import NIST256p
>>> print(NIST256p.curve)
CurveFp(p=115792089210356248762697446949407573530086143415290314195533631308867097853951, a=-3, b=41058363725152142129326129780047268409114441015993725554835256314039467401291, h=1)
>>>
```

※`h`はgmpy2が入ってない時に使うらしいので関係ない

これを用いてセッション中に次のパラメータが使われる。

```python
C = ecdsa.NIST256p
G = C.generator
n = C.order
k = random.randint(1,n-1)
```

以下の操作を100回繰り返し、その度に秘密鍵を当てる事が出来ればフラグが表示される。

1. 秘密鍵を生成する
2. パラメータ`k1`を`k1 = k+random.randint(1,4096)`で生成する。前述の`k`に対し4096までの自然数を加算するだけである。
3. 署名するメッセージを要求し署名を生成する。
4. 2と3をもう1度繰り返し2つの署名を生成する。それぞれ`(r1, s1), (r2, s2)`とする。
5. 配列`[r1, s1, r2, s2]`をシャッフルした上に1つランダムで除去しその結果を与える。
6. 入力を待ち、秘密鍵が提出されれば次のチャレンジが始まる。失敗したら即終了する。

### `s2`の入手

1回の署名でくれる数字は3つしか無いが、この内2つは正しい`r, s`の組となっているはずである。3つの数字から順序を考慮する取り出し方は6通りなのでこれらに対して署名の検証を行うことで署名として有効な`r, s`は取り出すことが出来る。以下ではこれを`r1, s1`とおく。

ここで残りの数字が`s`に相当するかを判定し、もしそうでなかったら接続をやり直す。この判定だが平方剰余を利用して次のようにする。

1. `r`は楕円曲線上の点のx座標なので仮に残りの数字が`r`であれば、{{katex(body="y^2 \equiv r^3 + ar + b \bmod p")}}となる{{katex(body="y")}}が存在するはずである。
2. これは平方剰余を使って判定出来る。もし、右辺が{{ katex(body="p") }}の平方剰余でない場合はこのような{{katex(body="y")}}は存在しないため`r`では無い、つまり`s`である事がわかる
    - 但し、`s`の場合でも平方剰余と判定されることは考えられるため`s`の必要十分条件を用いて判定出来るわけではない。
このようにして確定した`s`を`s2`とおく。

こうして未知の数字は`s2`と対応する署名の片割れである`r2`となる。

### `r2`の特定

ここで次のように値を定義する。

$$
k_1 = k + \alpha, \ k_2 = k + \beta, \ 1 \leq \alpha, \beta \leq 4096, \ \alpha \neq \beta
$$
$$
k_2 = k_1 + \delta
$$
$$
P_1 = k_1G, \ P_2 = k_2G = (k_1 + \delta)G = P_1 + \delta G
$$
$$
r_1 = {P_1}_x, r_2 = {P_2}_x
$$

ここで{{katex(body="\delta")}}は{{katex(body="-4095 \leq \delta \leq 4095")}}を満たすことから、{{katex(body="P_1")}}が与えられたら{{katex(body="\delta")}}をこの範囲で探索することで{{katex(body="P_2")}}を特定することが出来る。{{katex(body="\delta")}}はそこまで広くない上に計算した{{katex(body="P_2")}}のx座標が{{katex(body="r_2")}}になるため、既に与えられている`s2`と署名の検証をすることで、現実的な範囲とアルゴリズムで{{katex(body="r_2")}}を特定することができる。

では肝心の{{katex(body="P_1")}}の特定だが、これは方程式{{katex(body="y^2 \equiv r_1^3 + ar_1 + b \bmod p")}}を満たすような{{katex(body="y")}}を求めれば良い。単純にTonelli-Shanksのアルゴリズムでも良いが、NIST P-256曲線で使われている素数は{{katex(body="p = 4k+3")}}の形なのでもっと簡単に求めることが出来る(フェルマーの小定理を適用するだけなので略)。

これで求まる{{katex(body="y")}}は2通りなのでこれら2つに対してそれぞれこの探索を行うことで{{katex(body="r_2")}}を求めることが出来る。

※下記コードはyの対称性を使って上手く探索の計算量を抑えようとしたんですが、どうも半分ぐらいの確率で失敗します。直すのと検証面倒なのでそのままです。

### 1回目の秘密鍵の特定

前述の手順では{{katex(body="P_1")}}に{{katex(body="G")}}を足していくことで{{katex(body="P_2")}}のx座標として正しいものを特定したため、この足した回数、つまり{{katex(body="\delta")}}も特定出来たことになる。ここで2つの署名`s_1, s_2`に関して次のような関係がある。

$$
s_1 \equiv \frac{z + r_1d}{k_1} \bmod n, \ s_2 \equiv \frac{z + r_2d}{k_1 + \delta} \bmod n
$$

但し{{katex(body="n")}}は曲線の位数、{{katex(body="z")}}は署名したメッセージをSHA-256にかけたもので、{{katex(body="d")}}は秘密鍵である。

2つの未知数{{katex(body="k_1, d")}}に対して2つの式があるのでどちらも特定可能である。具体的には次のようにすることで{{katex(body="d")}}を特定出来る。

$$
d \equiv \frac{s_1}{s_1r_2 - s_2r_1}\left(\delta s_2 + \left(\frac{s_2}{s_1} - 1\right)z\right) \bmod n
$$

### 2回目以降の秘密鍵の特定

前節で{{katex(body="d")}}が求まったので1回目の{{katex(body="k_1")}}も求めることが出来る。2回目以降の署名も`k`に4096までの自然数を足したものが`k_1, k_2`として使われることは変わらないため、1回目で求めた`k_1`を{{katex(body="k_0")}}とおくと、以降の`k_1, k_2`対して次が成り立つ。

$$
k_0 - 4095 \leq k_1, k_2 \leq k_0 + 4095
$$

2回目以降も正しい署名を1つは手に入れることが出来、その署名で使われた`k_1`はこの範囲に収まる事から事前にこの範囲で{{katex(body="k_1G")}}を計算しておき、x座標をキーとし、{{katex(body="k_0")}}との差を値とした辞書を作っておけば2回目以降特定出来た`r_1`はこの辞書のキーに含まれ、`k_1`を特定することが出来る。

`k_1`が求まったということは{{katex(body="d")}}も求めることが出来るため、2回目以降の署名はこれを提出すれば良い。

これを100回やると無事にフラグが表示された。

## Code

探索をサボっているせいか`s_2`の入手に成功しても`r_2`の特定にそこそこの確率で失敗します。

※楕円曲線上と有限体上の演算は自前のものを使っているので適宜読み替えてください

```python
from pwn import remote
import hashlib, hashlib
from itertools import permutations
from xcrypto import ECPoint, EllipticCurve, Element, is_quadratic_residue


# connection info
target = "localhost"
port = 13337

# curve paramater
p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
a = -3
b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
ec = EllipticCurve(a, b, p)
g_x = 48439561293906451759052585252797914202762949526041747995844080717082404635286
g_y = 36134250956749795798585127919587881956611106672985015071877198253568414405109
g = ECPoint(g_x, g_y, ec)
n = 115792089210356248762697446949407573529996955224135760342422259061068512044369


def create_conn(c=None):
    ret = remote(target, port)

    if c is not None:
        ret.recvuntil(c)

    return ret


def verify(r, s, z, q):
    w = pow(s, -1, n)
    u, v = z * w % n, r * w % n
    return (u*g + v*q).unpack()[0] == r


def detect_signature(num_list, z, q):
    rs_list = permutations(num_list)
    for r, s, other in rs_list:
        if verify(r, s, z, q):
            return ([r, s], other)

    print("[+] invalid signature")
    exit()


def get_y(x):
    k = p // 4
    rhs = (x**3 + a*x + b) % p
    y = pow(rhs, -k, p)
    if y**2 % p != rhs:
        return None

    return (y, -y % p)


def get_params(sc):
    sc.recvuntil("> ROUND")
    sc.recvline()
    q = list(map(int, sc.recvline().strip().split()))
    q = ECPoint(q[0], q[1], ec)
    sc.recvuntil("first message: ")
    sc.sendline(b"unko")
    sc.recvuntil("second message: ")
    sc.sendline(b"unko")
    z = int(hashlib.sha256(b"unko").hexdigest(), 16)
    nums = list(map(int, sc.recvline().strip().split()))
    return nums, z, q


def calc_r2(nums, z, q):
    rs, other = detect_signature(nums, z, q)
    if is_quadratic_residue(other, n):
        print("[+] failed to get `r2`")
        exit()
    r, s = rs
    ys = get_y(r)
    found = False

    # params for verification
    w = pow(other, -1, n)
    u = z * w % n
    ug = u*g

    for y in ys:
        p1 = ECPoint(r, y, ec)
        p2 = p1
        for delta in range(1, 4096):
            if delta % 256 == 0:
                print(delta)
            p2 += g
            r2 = p2.unpack()[0]
            v = r2 * w % n
            vq = v*q
            if (ug + vq).unpack()[0] == r2:
                found = True
                break
        if found:
            break

    if found:
        return (r, s, r2, other, delta)

    print("[+] failed to get `r2`")
    exit()


def calc_d(r1, s1, r2, s2, z, delta, q):
    r1 = Element(r1, n)
    s1 = Element(s1, n)
    r2 = Element(r2, n)
    s2 = Element(s2, n)
    z = Element(z, n)

    for _ in range(2):
        delta *= -1
        _delta = Element(delta, n)
        d = (s1 / (s1*r2 - s2*r1)) * (_delta * s2 + (s2 / s1 - Element(1, n)) * z)
        if d.x * g == q:
            return d.x, _delta.x

    return None


def calc_k(sc):
    nums, z, q = get_params(sc)
    r1, s1, r2, s2, delta = calc_r2(nums, z, q)
    d, delta = calc_d(r1, s1, r2, s2, z, delta, q)
    sc.recvuntil("number?\n")
    sc.sendline(str(d))
    print(sc.recvline())
    k_alpha = (z + r1 * d) * pow(s1, -1, n) % n
    assert (z + r1*d) * pow(k_alpha, -1, n) % n == s1 and s2 == (z + r2*d) * pow(k_alpha + delta, -1, n) % n

    return k_alpha


def exploit(sc):
    k = calc_k(sc)
    if k is None:
        print("[+] Please retry.")
        exit()
    print("[+] found!!", k)

    r_dict = {}
    start = (k - 4096) * g
    for delta in range(-4096, 4096):
        r_dict[start.unpack()[0]] = delta
        start += g

    for _ in range(99):
        nums, z, q = get_params(sc)
        rs, other = detect_signature(nums, z, q)
        r, s = rs
        k_alpha = k + r_dict[r]

        d = (s * k_alpha - z) * pow(r, -1, n) % n
        assert d * g == q
        sc.recvuntil("number?\n")
        sc.sendline(str(d))
        print(sc.recvline())


if __name__ == '__main__':
    sc = create_conn()
    exploit(sc)

    sc.interactive()
    sc.close()

```

## Flag

ローカルですが、公式のリポジトリにフラグがあったのでそこで動かしました。

`flag{s0m3t1m3s_crypt0gr4ph1c_1mpl3m3nt4t10ns_f41l}`

## リンク

- 運営リポジトリ: <https://github.com/redpwn/redpwnctf-2020-challenges/tree/master/crypto/speedy-signatures>
