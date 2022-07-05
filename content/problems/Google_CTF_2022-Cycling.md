+++
title = "Google CTF 2022 - Cycling"
date = 2022-07-05

[taxonomies]
tags = ["CTF", "Writeup", "Crypto", "RSA", "carmichael_function"]
+++

- 問題ファイル: <https://github.com/google/google-ctf/blob/master/2022/crypto-cycling/src/chall.py>

## TL;DR

- RSAのCycle Attackというもので用いる暗号化回数が与えられる
- これを用いると実質的に$\lambda(\lambda(n))$が分かる
- その逆演算は一意に定まらないが、$\lambda(n)$の倍数を求める事は出来るのでこれを利用して復号出来る

## Prerequisite

- カーマイケル関数

## Writeup

次のようなスクリプトが渡される

```python
#!/usr/bin/python3

# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
It is well known that any RSA encryption can be undone by just encrypting the
ciphertext over and over again. If the RSA modulus has been chosen badly then
the number of encryptions necessary to undo an encryption is small.
If n = 0x112b00148621 then only 209 encryptions are necessary as the following
example demonstrates:

>>> e = 65537
>>> n = 0x112b00148621
>>> pt = 0xdeadbeef
>>> # Encryption
>>> ct = pow(pt, e, n)
>>> # Decryption via cycling:
>>> pt = ct
>>> for _ in range(209):
>>>   pt = pow(pt, e, n)
>>> # Assert decryption worked:
>>> assert ct == pow(pt, e, n)

However, if the modulus is well chosen then a cycle attack can take much longer.
This property can be used for a timed release of a message. We have confirmed
that it takes a whopping 2^1025-3 encryptions to decrypt the flag. Pack out
your quantum computer and perform 2^1025-3 encryptions to solve this
challenge. Good luck doing this in 48h.
"""

e = 65537
n = 0x99efa9177387907eb3f74dc09a4d7a93abf6ceb7ee102c689ecd0998975cede29f3ca951feb5adfb9282879cc666e22dcafc07d7f89d762b9ad5532042c79060cdb022703d790421a7f6a76a50cceb635ad1b5d78510adf8c6ff9645a1b179e965358e10fe3dd5f82744773360270b6fa62d972d196a810e152f1285e0b8b26f5d54991d0539a13e655d752bd71963f822affc7a03e946cea2c4ef65bf94706f20b79d672e64e8faac45172c4130bfeca9bef71ed8c0c9e2aa0a1d6d47239960f90ef25b337255bac9c452cb019a44115b0437726a9adef10a028f1e1263c97c14a1d7cd58a8994832e764ffbfcc05ec8ed3269bb0569278eea0550548b552b1
ct = 0x339be515121dab503106cd190897382149e032a76a1ca0eec74f2c8c74560b00dffc0ad65ee4df4f47b2c9810d93e8579517692268c821c6724946438a9744a2a95510d529f0e0195a2660abd057d3f6a59df3a1c9a116f76d53900e2a715dfe5525228e832c02fd07b8dac0d488cca269e0dbb74047cf7a5e64a06a443f7d580ee28c5d41d5ede3604825eba31985e96575df2bcc2fefd0c77f2033c04008be9746a0935338434c16d5a68d1338eabdcf0170ac19a27ec832bf0a353934570abd48b1fe31bc9a4bb99428d1fbab726b284aec27522efb9527ddce1106ba6a480c65f9332c5b2a3c727a2cca6d6951b09c7c28ed0474fdc6a945076524877680
# Decryption via cycling:
pt = ct
for _ in range(2**1025 - 3):
  pt = pow(pt, e, n)
# Assert decryption worked:
assert ct == pow(pt, e, n)

# Print flag:
print(pt.to_bytes((pt.bit_length() + 7)//8, 'big').decode())

```

RSAにはCycle Attackというものが存在し、不適切な$n$を選ぶと$n$の大きさに対して十分小さい回数の暗号化の繰り返しで平文を復元出来るらしい。スクリプトのコメントには例として`n = 0x112b00148621`の場合が添えられており、この場合は暗号文を209回暗号化をすることで平文に戻る。

問題の$n$でもこれに該当する回数が存在するが、そもそも$n$が2048bitと大きいことから、この回数も非常に大きくなる。そしてその回数はなんと$2^{1025} - 3$回であり、CTF期間中どころか人類が滅ぶぐらいの時間が経過しそうである。

というわけで、$n$に対して、追加のヒントとしてこの回数が与えられているという状況で暗号文を復号出来るかという問題になる。

---

この繰り返しの回数を$k$とおくと、次が成り立っている。

$$
m \equiv c^{(e^k)}  \mod n
$$

ここで、$c\equiv m^e \mod n$であるから、$m \equiv (m^{e})^{(e^k)} \equiv m^{(e^{k+1})} \mod n$が成り立つ。$m$を$e^{k+1}$乗すると元に戻る事を考えると$e^{k+1} \equiv 1 \mod \lambda(n)$であることが分かる[^1]。ここで$\lambda$はカーマイケル関数である。更にこの式も$e$を$k+1$乗すると1になる事を言っているので、$k+1 \equiv 0 \mod \lambda(\lambda(n))$であると考えられる[^2]。$k+1$が無駄なく最も良い形で与えられているとしたら、$k+1 = \lambda(\lambda(n))$となり、以下ではこの仮定の下、議論を進める(実際、スクリプト記載のsmall exampleでは$\lambda(\lambda(n)) = 209+1$となっている)。

この問題では$k+1 = 2^{1025} - 2$となっており、これの素因数分解は比較的綺麗な形になる。具体的には指数が2以上の素因数が存在せず$k+1 = \prod_{i=1}^l p_i$という$l$個の素因数に分解出来る。なお、SageMathの`factor()`は時間がかかったので珍しく[factorDB](http://factordb.com/index.php?query=359538626972463181545861038157804946723595395788461314546860162315465351611001926265416954644815072042240227759742786715317579537628833244985694861278948248755535786849730970552604439202492188238906165904170011537676301364684925762947826221081654474326701021369172596479894491876959432609670712659248448274430)を用いたら出てきた。

カーマイケル関数の定義を用いると$x = \prod_{i=1}^{l'} p_i^{e_i}$とした時に、$\lambda(x) = \mathrm{lcm}(\lambda(p_1^{e_1}), \lambda(p_2^{e_2}), \dots, \lambda(p_{l'}^{e_{l'}}))$となる。更に奇素数$p$に対しては$\lambda(p^{e'}) = p^{e'-1}(p-1)$が成り立つ。

したがって、$x$の素因数$p_i$に対して$p_i-1$は$\lambda(x)$の約数であることがわかる。また、今回は$\lambda(x)$の素因数に指数が2以上のものが含まれないので$e_i \leq 2$であることもわかる。よって、$\lambda(x)$の約数を全部列挙し、それに1を足した結果が素数であれば、$x$の素因数である可能性がある。このような値を$p'$として$p'^2$全ての積を計算すれば、それは$x$の倍数となっている(ただし、CTF中は$p'^2$の2乗を見逃していて、$p'$の総積だけを計算したが、運良く解けた)。

さて、問題のインスタンスに戻ると$x$に相当するのは$\lambda(n)$である。よって、この方法で$\lambda(n)$の倍数を計算出来るので$C\lambda(n)$とする。ちなみに、$k+1 = \lambda(\lambda(n))$の約数は$2^{17}$個ぐらいあったが、1を足して素数になるのは600通りぐらいだったので総積を計算出来た。

これを用いて$ed \equiv 1 \mod C\lambda(n)$を計算する。このような$d$を用いて復号すると次のようになる。

$$
c^d \equiv m^{ed} \equiv m^{1 + C'C\lambda(n)} \equiv m \mod n
$$

ここで、$C'$は$ed - 1 = C'C\lambda(n)$を満たす整数である。そして合同の最後の変形は$m^{\lambda(n)} \equiv 1 \mod n$を用いた。

よって、$m$が復号出来たことになり、フラグが手に入る。

## Code

約数の列挙とそこから$\lambda(n)$の倍数を復元するところまで(復号は別コード)

```python
from itertools import product
from Crypto.Util.number import isPrime
from tqdm import tqdm


e = 65537
n = 0x99efa9177387907eb3f74dc09a4d7a93abf6ceb7ee102c689ecd0998975cede29f3ca951feb5adfb9282879cc666e22dcafc07d7f89d762b9ad5532042c79060cdb022703d790421a7f6a76a50cceb635ad1b5d78510adf8c6ff9645a1b179e965358e10fe3dd5f82744773360270b6fa62d972d196a810e152f1285e0b8b26f5d54991d0539a13e655d752bd71963f822affc7a03e946cea2c4ef65bf94706f20b79d672e64e8faac45172c4130bfeca9bef71ed8c0c9e2aa0a1d6d47239960f90ef25b337255bac9c452cb019a44115b0437726a9adef10a028f1e1263c97c14a1d7cd58a8994832e764ffbfcc05ec8ed3269bb0569278eea0550548b552b1
ct = 0x339be515121dab503106cd190897382149e032a76a1ca0eec74f2c8c74560b00dffc0ad65ee4df4f47b2c9810d93e8579517692268c821c6724946438a9744a2a95510d529f0e0195a2660abd057d3f6a59df3a1c9a116f76d53900e2a715dfe5525228e832c02fd07b8dac0d488cca269e0dbb74047cf7a5e64a06a443f7d580ee28c5d41d5ede3604825eba31985e96575df2bcc2fefd0c77f2033c04008be9746a0935338434c16d5a68d1338eabdcf0170ac19a27ec832bf0a353934570abd48b1fe31bc9a4bb99428d1fbab726b284aec27522efb9527ddce1106ba6a480c65f9332c5b2a3c727a2cca6d6951b09c7c28ed0474fdc6a945076524877680
k = 2**1025 - 3 + 1

# http://factordb.com/index.php?query=359538626972463181545861038157804946723595395788461314546860162315465351611001926265416954644815072042240227759742786715317579537628833244985694861278948248755535786849730970552604439202492188238906165904170011537676301364684925762947826221081654474326701021369172596479894491876959432609670712659248448274430
factors = [2, 3, 5, 17, 257, 641, 65537, 274177, 2424833, 6700417, 67280421310721, 1238926361552897, 59649589127497217, 5704689200685129054721, 7455602825647884208337395736200454918783366342657, 93461639715357977769163558199606896584051237541638188580280321, 741640062627530801524787141901937474059940781097519023905821316144415759504705008092818711693940737]

divs = []
michael = 1
for isdivs in tqdm(product([0,1], repeat=16)):
    prod = 2
    for isdiv, x in zip(isdivs, factors[1:]):
        if isdiv == 1:
            prod *= x
    if isPrime(prod + 1):
        divs.append(prod + 1)
        michael *= (prod + 1)

print(len(divs))
print(michael)
```

## Flag

`CTF{Recycling_Is_Great}`

---

[^1]: 正確には特定の平文$m$についてのみ成り立つことしか分かっていないが、任意の$m$についても成り立つだろうという仮定を用いた

[^2]: ここに関しても$e$に対してのみ成り立つことしか分かっていない(つまり$e$の$\mathbb Z_{\lambda(n)}^*$における位数が$k+1$であるという事実しかわからない)が、任意の値についても成り立つだろうという仮定を用いた
