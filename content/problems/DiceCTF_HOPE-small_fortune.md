+++
title = "DiceCTF @ HOPE - small-fortune"
date = 2022-07-25

[taxonomies]
tags = ["CTF", "Writeup", "Crypto", "Coppersmith's Attack", "Goldwasser-Micali"]
+++

## TL;DR

- Goldwasser-Micali暗号
- 暗号化に使うビットごとの乱数の差が小さい
- 最初に使われた乱数の2乗は求まることから、それを利用して差分を変数とした合同方程式を`small_roots()`で解き、解が存在するビットを平文とする

## Prerequisite

- [Goldwasser–Micali cryptosystem](https://en.wikipedia.org/wiki/Goldwasser%E2%80%93Micali_cryptosystem)

## Writeup

次のようなスクリプトとその実行結果が与えられる

```python
from Crypto.Util.number import *
from gmpy2 import legendre

flag = bytes_to_long(open("flag.txt", "rb").read())

p, q = getPrime(256), getPrime(256)
n = p * q

x = getRandomRange(0, n)
while legendre(x, p) != -1 or legendre(x, q) != -1:
    x = getRandomRange(0, n)

def gm_encrypt(msg, n, x):
    y = getRandomRange(0, n)
    enc = []
    while msg:
        bit = msg & 1
        msg >>= 1
        enc.append((pow(y, 2) * pow(x, bit)) % n)
        y += getRandomRange(1, 2**48)
    return enc

print("n =", n)
print("x =", x)
print("enc =", gm_encrypt(flag, n, x))
```

明らかにGoldwasser-Micali暗号が使われているが、各ビットに使う乱数`y`の差が`n`に比べて小さい。

公開鍵$n,e$に対して、ビット$b_i$の暗号文を$c_i$とおくと、暗号化に用いる乱数$y_i$を用いて次が成り立つ。

$$
c_i \equiv {y_i}^2x^{b_i} \mod n
$$

ここで、$i$がインクリメントされる度に$y_i$は最大で$2^{48}$程度加算されるが、これは$n$比べて非常に小さい。よって、$y_i$と$y_0$の差も$n$に比べて小さくなることから次のように書き直す。

$$
c_i \equiv (y_0+\delta_i)^2x^{b_i} \mod n
$$

ここで、$b_0$は0か1かの2択であり、フラグがフォーマットに沿っていて改行も存在していないとすれば、`ord("}") = 0x7d`より奇数であるから、$b_0=1$としてよい。よって$y_0^2 \equiv \frac{c_i}{x} \mod n$が成り立つ。

上記の$c_i$に関する式を見直すと、$(y_0+\delta_i)^2 = y_0^2+2\delta_i y_0 + \delta_i^2$が現れ、$y_0^2$が既知であることから、後は$y_0$を消去出来れば良い事になる。これは明らかに$y_0$について解いて2乗すれば良く、最終的に次のような式が得られる。

$$
\left(\frac{c_i}{x^{b_i}} - y_0^2 -\delta_i^2\right)^2 - 4\delta_i y_0^2 \equiv 0 \mod n
$$

ここで、もし$b_i$を正しくGuess出来たとしたら、$\delta_i$が$n$に比べて小さく、更に$\delta_i$は左辺の根の1つなのでCoppersmith's Attackで求められることが期待出来る。そして$b_i$は0,1の高々2通りなので総当たり出来ることを利用すれば、どちらも`small_roots()`を試して解が存在したら、$b_i$のGuessが成功したことになる。

## Code

```python
from output import n, x, enc
from Crypto.Util.number import long_to_bytes
from tqdm import tqdm


R = Zmod(n)
PR.<delta> = PolynomialRing(R)
# assumption: lsb of the flag is 1
y2 = inverse_mod(x, n) * enc[0] % n

flag = "1"
for c in tqdm(enc[1:]):
    found = False
    for b in [0,1]:
        lhs = (c * power_mod(x, -b, n) - y2) % n
        f = (lhs - delta**2)**2 - 4*delta**2*y2
        rs = f.small_roots(epislon=1/20)
        if len(rs) != 0:
            if found:
                print("[+] ha? (1)")
            flag = str(b) + flag
            found = True

    if not found:
        print("[+] ha? (2)")

print(flag)
flag = int(flag, 2)
print(long_to_bytes(flag))
```

## Flag

`hope{r4nd0m_sh0uld_b3_truly_r4nd0m_3v3ry_t1m3_sh0uld_1t_n0t?}`
