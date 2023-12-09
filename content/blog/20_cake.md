+++
title = "Writeup: CakeCTF 2021"
date = 2021-08-30

[taxonomies]
tags = ["CTF", "Writeup", "Crypto", "Lattice"]
+++

先週土日に開催されていたCakeCTF 2021に出たので自分が解いた問題のWriteupを書きます

<!-- more -->

## Table of Contents

- [Together as one](https://project-euphoria.dev/blog/20-cake/#together-as-one)
- [Matrix Cipher](https://project-euphoria.dev/blog/20-cake/#matrix-cipher)

## Together as one

次のようなスクリプトとその実行結果が与えられる。

```Python
from Crypto.Util.number import getStrongPrime, bytes_to_long

p = getStrongPrime(512)
q = getStrongPrime(512)
r = getStrongPrime(512)

n = p*q*r

x = pow(p + q, r, n)
y = pow(p + q*r, r, n)

m = bytes_to_long(open("./flag.txt", "rb").read())
assert m.bit_length() > 512
c = pow(m, 0x10001, n)

print(f"{n = :#x}")
print(f"{c = :#x}")
print(f"{x = :#x}")
print(f"{y = :#x}")

```

3つの素数を用いたMulti Prime RSAで、公開鍵と暗号文の他にヒントとして`x,y`という値が与えられる。これらは公開鍵の素因数である素数を{{katex(body="p,q,r")}}とおく(つまり{{katex(body="n = pqr")}})と、次のようになっている。

$$
\begin{aligned}
x &\equiv (p+q)^r \bmod n \cr
y &\equiv (p+qr)^r \bmod n
\end{aligned}
$$

これは二項定理を用いると次のように変形出来る。

$$
\begin{aligned}
x &\equiv p^r + q^r \bmod n \cr
y &\equiv p^r + (qr)^r \bmod n \cr
\end{aligned}
$$

1つ目の式の変形については、{{katex(body="p^r, q^r")}}以外の二項係数が必ず{{katex(body="r")}}の倍数になる事から{{katex(body="N")}}を法として0になることから消去出来る。2つ目の式については特に言うことは無い。

ここから{{katex(body="x-y \equiv q^r(1-r^r) \bmod n")}}が成立し、{{katex(body="n")}}が{{katex(body="q")}}の倍数であることから、{{katex(body="x-y")}}も{{katex(body="q")}}の倍数になる(非自明ですが法を外してみるとわかります)。

これで{{katex(body="q")}}の倍数が{{katex(body="n, x^y")}}と2つ手に入ったので最大公約数を求めれば{{katex(body="q")}}が出てくる事が期待出来る。

ここで{{katex(body="x-y = q^r(1 - r^r) + kpqr")}}と整数{{katex(body="k")}}を用いて書く事が出来るので{{katex(body="r")}}で法をとると{{katex(body="x-y \equiv q^r \equiv q \bmod r")}}となる。一番最後の変形はフェルマーの小定理を用いた。

よって{{katex(body="x-y-q")}}が{{katex(body="r")}}の倍数になるので先程同様に最大公約数をとれば{{katex(body="r")}}が求まり、当然{{katex(body="p")}}も求まるので、後はRSAの復号手順を経るだけ。

使用コードは次の通り

```Python
from Crypto.Util.number import getStrongPrime, bytes_to_long, long_to_bytes
from math import gcd


if __name__ == "__main__":
    n = 0x94cf51734887aa44204e7d64ed2b30763fd0715060afd5d15b697c940c272422b4ca765485f7c3116db1166ad1fec4cd4d82d3b32e881ed49f52efe31a226b307d60f2fb375400f9a19b0142e7d88d6118e02971724186e1ef13e586c744240b3ee7d6a105b82a3e3126ae364550e9b3a19d6b012083b8633ad428cf75cb200fe31121e6bf095418c5ed3819225910bc69ebe2e6a219638b830df45015c75ca9a507dc924718a540cfb5d2df09ff28d7cf8feb0e5e69a3d71057004132bb3e79
    x = 0x38f530204337208b5bbfadd20fcd4416d8be1563c338c0ba464abbcd3699794c0c8e0b6f17f41bc5e42dd5f900d3644b34f4530157cc8c026894f97f2feb5475e58cdf9125d96bdae25bbf6afdf58129c8e1c70a5b47f2dbe3f89e851c124bed2b40f6e8ec8d6d3ff941fa5dcde893c661059fffdb5086863e35228bc79b1ba830555c3168c88a53e3c7eee17312c401914442d4e04c5014aa484994d0c680980f53aeef01c9c246ec76dcdf8816036b77629610709ccc533cbd09a818146060
    y = 0x607e4383ee2f5bb068a4fb51205396c784a56e971cee8f2b2c79fbf1ce4161a4031aa10df22723005024ef592764c4391f31ca35137221a7431c68033b5f92ab5bf9c660e5cda375faf4f4e734cb8745d0b7b056b2d9ba38a733fae118f07ceb1af4fbb2818b6cf4394f166f3790a9ad39efb27a970399ed1fc04b96a282681109825c96e3784f1ee3ac1a787f28dd7c74cc6cccecffb0ce534e1ed7192ccc2bc3f822ad16dc42608d6fe1de447e4ed9474d1113bd0514d1f90b92f04769059
    c = 0x8c0450dff19d853673d51cb2eab4cb84ffa7fa3eba900c1e96adbb2ccb6708320233e18b2d6ce487dbfb88f15b0ccac5829818ca49ac8ab08a1e5b94e27550798e6d1aae48812b784144dc7bed55cec6283042a296e25490990e07b8ff51b1a500b6d8c39af1c07c1ef57ca2b3774a4d38f6006a64f37133915f9afcbd08394e74c616fabd77d79cd9559a3eee41f2507556637bac6145bfba22319f424f07a33221a8fb9c89dc3c68e188230ed36e95a6baf977ca58d2036d136ebd55bd45d3

    q1 = x-y
    q = gcd(q1, n)
    
    assert n % q == 0
    pr = n // q

    r1 = x-y-q
    r = gcd(pr,r1)
    print(n % r)
    print(r)

    p = pr // r

    assert p*q*r == n

    phi = (p-1)*(q-1)*(r-1)
    d = pow(0x10001, -1, phi)
    m = pow(c, d, n)
    print(long_to_bytes(m))
```

Flag: `CakeCTF{This_chall_is_inspired_by_this_music__Check_out!__https://www.youtube.com/watch?v=vLadkYLi8YE_cf49dcb6a31f}`

凄い綺麗な問題だった。暫定で個人的Crypto of the Yearです。

## Matrix Cipher

次のようなスクリプトとその実行結果が与えられる。

```Python
with open("flag.txt", "rb") as f:
    flag = list(f.read().strip())

def hadamard(M):
    d = M.determinant()
    x = 1.0
    for row in M:
        x *= row.norm()
    return (d / x) ** (1.0/M.ncols())

def keygen(n, d):
    k = int(floor(sqrt(n) * d))
    while True:
        R = k * Matrix.identity(ZZ, n) + random_matrix(ZZ, n, n, x=-d, y=d)
        if  hadamard(R) >= 0.7:
            break

    B = R
    while True:
        U = random_matrix(ZZ, n, n, algorithm="unimodular")
        B = U * B
        if hadamard(B) <= 0.2:
            break

    return B, R

def encrypt(B, m):
    assert B.nrows() == len(m)
    return vector(ZZ, m) * B  + random_vector(ZZ, len(m), x=-50, y=50)

B, R = keygen(len(flag), 100)
c = encrypt(B, flag)

print(list(B))
print(c)

```

各成分がフラグの文字となっているベクトル{{katex(body="v")}}と公開鍵である行列{{katex(body="B")}}と値は不明だが各成分が小さいエラーベクトル{{katex(body="e")}}を用いて{{katex(body="c = vB + e")}}となっている。

ここで{{katex(body="B")}}を格子{{katex(body="L")}}の基底行列とみなせば{{katex(body="vB")}}は各基底の整数係数線形結合になるので、格子{{katex(body="L")}}上の点になる。ということはそれに微小なエラーベクトルを足しただけの{{katex(body="c")}}をターゲットとしてCVPを解けば{{katex(body="vB")}}を求めることが出来、{{katex(body="B")}}の逆行列を右から掛ければ{{katex(body="v")}}が得られそうである。

というわけでBabaiのアルゴリズムを用いてCVPを解いて一連の手順を経たらフラグが手に入った。

使用コードは次の通り

```Python
B = ...

c = ...

# Babai's Nearest Plane algorithm
# from: http://mslc.ctf.su/wp/plaidctf-2016-sexec-crypto-300/
# ↑は事前にLLLした基底とそれに対してグラムシュミットの直交化をしたものを渡さないといけないためやや修正
def Babai_closest_vector(M, target):
    M = M.LLL()
    G = M.gram_schmidt()[0]
    small = target
    for _ in range(1):
      for i in reversed(range(M.nrows())):
        c = ((small * G[i]) / (G[i] * G[i])).round()
        small -= M[i] * c
    return target - small


B = Matrix(ZZ, B)
c = vector(ZZ, c)

res = Babai_closest_vector(B, c)
print(res)
print(c)
print(res - c)

flag = res * B^(-1)
print(flag)

s_flag = ""
for c in flag:
    s_flag = s_flag + chr(c)

print(s_flag)
```

Flag: `CakeCTF{ju57_d0_LLL_th3n_s01v3_CVP_wi7h_babai}`

3rd Bloodだった、そういえば格子の拙記事にはCVPは無かったので気が向いたら第2弾を書きます(本当ですか?)。

## Links

- [運営開催記(ptr-yudaiさん)](https://ptr-yudai.hatenablog.com/entry/2021/08/30/000015)
  - Writeupを見つけただけ載せているの素晴らしい、これも載るかな(ﾜｸﾜｸ)
- [運営開催記(theoremoonさん)](https://furutsuki.hatenablog.com/entry/2021/08/29/224254)
  - 「難易度について」のところ100億回頷いた
- [公式リポジトリ](https://github.com/theoremoon/cakectf-2021-public)
  - InterKosenCTF時代のリポジトリも推奨
