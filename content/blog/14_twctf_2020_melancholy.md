+++
title = "TokyoWesterns CTF 6th 2020 - The Melancholy of Alice"
date = 2021-02-01

[taxonomies]
tags = ["CTF", "Writeup", "Crypto"]
+++

もうTWCTF 2020が開催されてから半年近く経ちますが、個人的にかなり好きでいつかWriteupを書こうと思っていた問題があるので書きます。問題はThe Melancholy of AliceでElGamal暗号の問題です。

<!-- more -->

## Prerequisite

下記事項は知っているものとしてWriteupを書きます。

- ElGamal暗号
- Pohlig-Hellmanアルゴリズムの"動作原理"

## Writeup

### Outline

1文字ずつ暗号化しているElGamal暗号で素数生成に`getStrongPrime`を使っている為、Pohlig-Hellmanアルゴリズムを直接使うのは難しい。しかし位数を素因数分解するとある程度小さい素数を因数として含んでいる為、それらの積を法とする解は判明する。そこから本来の復号手順に似た計算をすると平文に対し一意な結果が現れる為、事前に計算しておいてそれと照合する事で復号出来る。

### 配布スクリプト

次のような暗号化スクリプトとその実行結果をくれる

```python
from Crypto.Util.number import getStrongPrime, getRandomRange

N = 1024


def generateKey():
    p = getStrongPrime(N)
    q = (p - 1) // 2
    x = getRandomRange(2, q)
    g = 2
    h = pow(g, x, p)
    pk = (p, q, g, h)
    sk = x
    return (pk, sk)


def encrypt(m, pk):
    (p, q, g, h) = pk
    r = getRandomRange(2, q)
    c1 = pow(g, r, p)
    c2 = m * pow(h, r, p) % p
    return (c1, c2)


def main():
    with open("flag.txt") as f:
        flag = f.read().strip()

    pk, sk = generateKey()
    with open("publickey.txt", "w") as f:
        f.write(f"p = {pk[0]}\n")
        f.write(f"q = {pk[1]}\n")
        f.write(f"g = {pk[2]}\n")
        f.write(f"h = {pk[3]}\n")

    with open("ciphertext.txt", "w") as f:
        for m in flag:
            c = encrypt(ord(m), pk)
            f.write(f"{c}\n")


if __name__ == "__main__":
    main()

```

通常のElGamal暗号を1文字ずつ平文に適用している。離散対数問題といえばPohlig-Hellmanアルゴリズムというところがあるが、法に安全素数が使われているようなので適用は難しい。

### 脆弱性

1. 1文字ずつ暗号化している。
2. `getStrongPrime`を使用しているが、位数はある程度の小さな素数までなら素因数分解出来る

まず1. の1文字ずつの暗号化であるが、どのような暗号文になるかがわかっていればその暗号文から逆に辿る事で平文を特定出来る。ElGamalは確率的アルゴリズムを使っているので毎回暗号文は異なるのだが、暗号文が2つのペアであることからこれを上手く使う(後述)とそのランダム性を消す事が出来る。

続いて2. についてだが、このスクリプトで使用されている素数{{katex(body="p")}}は`getStrongPrime`で生成しているにも関わらず位数{{katex(body="p-1")}}は次のように素因数分解出来る。

$$
p - 1 = 2 \times 3 \times 5 \times 19 \times 5710354319 \times C
$$

ここで{{katex(body="C")}}はなんらかの大きな数である。これより、Pohlig-Hellmanアルゴリズムを5710354319までの数で適用すれば{{katex(body="p")}}を法とする離散対数問題は{{katex(body="2 \times 3 \times 5 \times 19 \times 5710354319")}}を法とする解を得る事が出来る。

### Pohlig-Hellmanアルゴリズムの部分適用

生成元を{{katex(body="g")}}、公開鍵を{{katex(body="h")}}とおくと、秘密鍵{{katex(body="x")}}は{{katex(body="h \equiv g^x \bmod p")}}を満たしている。ここで、Pohlig-Hellmanアルゴリズムをそのまま使うのでは無く、一部の素因数において適用すると、この素因数の積{{katex(body="P := \prod_i p_i")}}を法とした解を得る事が出来る。ここで求められた解を{{katex(body="x'")}}とおくと本来の解{{katex(body="x")}}との間に次が成り立つ。

$$
x = x' + kP = x' + k \frac{p-1}{C}
$$

但し{{katex(body="k")}}は何らかの整数である。

ここで{{katex(body="g")}}を{{katex(body="x")}}乗すると

$$
g^x \equiv g^{x'} g^{k \frac{p-1}{C}} \bmod p
$$

のようになり、これを更に両辺{{katex(body="C")}}乗すると

$$
g^{Cx} \equiv g^{Cx'} g^{k(p-1)} \equiv g^{Cx'} \bmod p
$$

となる。最右辺の変形にはフェルマーの小定理を利用した。

### 暗号文から平文の特定

ここでElGamal暗号の暗号文は2つの数字のペア{{katex(body="(c_1, c_2)")}}であり、{{katex(body="c_1 \equiv g^r \bmod p, \ c_2 \equiv mh^r \bmod p")}}を満たしている。先程求めた{{katex(body="x'")}}で復号を試みてみると次のようになる。

$$
\frac{c_2}{c_1^{x'}} \equiv \frac{mh^r}{g^{rx'}} \equiv m g^{r(x - x')} \bmod p
$$

ここで前節で求めた{{katex(body="g^{Cx} \equiv g^{Cx'}")}}を利用すると前式を{{katex(body="C")}}乗する事で次のようになる。

$$
\left(\frac{c_2}{c_1^{x'}}\right)^C \equiv m^C g^{r(Cx - Cx')} \equiv m^C \bmod p
$$

ここで{{katex(body="m")}}は1文字である事から{{katex(body="m^C \bmod p")}}を全ての{{katex(body="m")}}について計算しておく事で{{katex(body="\left(\frac{c_2}{c_1^{x'}}\right)^C")}}と照合すると、暗号文ペアに対応する{{katex(body="m")}}が判明する。

## Code

- Python 3.8系
- `xcrypto`は自作のライブラリ

```python
from ciphertext import cs
from xcrypto import prod, pohlig_hellman


if __name__ == '__main__':
    p = 168144747387516592781620466787069575171940752179672411574452734808497653671359884981272746489813635225263167370526619987842319278446075098036112998679570069486935297242638675590736039429506131690941660748942375274820626186241210376537247501823653926524570571499198040207829317830442983944747691656715907048411
    q = 84072373693758296390810233393534787585970376089836205787226367404248826835679942490636373244906817612631583685263309993921159639223037549018056499339785034743467648621319337795368019714753065845470830374471187637410313093120605188268623750911826963262285285749599020103914658915221491972373845828357953524205
    g = 2
    h = 98640592922797107093071054876006959817165651265269454302952482363998333376245900760045606011965672215605936345612030149799453733708430421685495677502147392514542499678987737269487279698863617849581626352877756515435930907093553607392143564985566046429416461073375036461770604488387110385404233515192951025299
    
    phi_factors = [2, 3, 5, 19, 5710354319, 4588812059915964626441195986601,
            430923798952014626471778738183277193,
            26124298782684438590021185331267988846966706118240279659453467110787128645190976897077818080910742463527776263317303686813251444118479303786495068060802647808279678377670781988776804559559478165988611476824171111029852087414508239]

    p_prod = prod(phi_factors[0:5])
    c = (p-1) // p_prod

    to_pohlig_hellman_list = []
    for _p in phi_factors[0:5]:
        to_pohlig_hellman_list.append((_p, 1))

    _x = pohlig_hellman(g, h, p, to_pohlig_hellman_list, True)
    print(_x)

    m_pow_c_dict = {}
    for i in range(128):
        res = pow(i, c, p)
        if res in m_pow_c_dict:
            print("[+] Doubled!!", i)
            m_pow_c_dict[res].append(i)
        else:
            m_pow_c_dict[res] = [i]

    flag = ""
    for c1, c2 in cs:
        res = pow(pow(pow(c1, _x, p), -1, p) * c2, c, p)
        if res not in m_pow_c_dict:
            print("[+] ha?")
        else:
            flag += chr(m_pow_c_dict[res][0])

    print(flag)
    print("[+] Done")
```

## Flag

`TWCTF{8d560108444cc360374ef54433d218e9_for_the_first_time_in_9_years!}`
