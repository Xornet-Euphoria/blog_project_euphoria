+++
title = "Writeup: kurenaif Valentine Problems"
date = 2021-02-14

[taxonomies]
tags = ["CTF", "Writeup", "Crypto"]
+++

IT魔女Vtuberのkurenaifさんが登録者数1000人とバレンタインを記念して問題セットをリリースしていたので5問中4問解きました。残り1問は卒論発表が片付いたら挑む予定です。

問題はこちら: <https://github.com/kurenaif/kurenaif_valentine_problems>

作問者Writeupはこちら: <https://zenn.dev/kurenaif/articles/f9d3f56e1d3235>

<!-- more -->

## p_p_rsa

次のようなスクリプトとその実行結果をくれる。

```python
from Crypto.Util.number import *
from flag import *
import secrets

m = bytes_to_long(flag)

p = getPrime(256)
q = p # Oops!
N = p*q
e = 65537
print("e =", e)
print("N =", N)
print("c =", pow(m, e, N))


```

RSA暗号の公開鍵{{katex(body="N")}}が2つの素数の積になっているので素因数分解は簡単に出来る。この時、秘密鍵{{katex(body="d")}}は{{katex(body="d := e^{-1} \bmod \phi(N)")}}であり、{{katex(body="\phi(p^2) = p(p-1)")}}である事に注意して計算すると無事に復号出来る。

使用コードは次の通り(自作ライブラリ使用)

```python
from Crypto.Util.number import long_to_bytes
from xcrypto import int_nth_root


if __name__ == "__main__":
    e = 65537
    N = 7504521114311153672308826977564891107288058227100173341193360340321176562970983694756086045753375611733443716948010092176135133045533366956059169702726409
    c = 3120246791506259955679234385495683489853187127801200033777823093969698684663885288175101358075188702658492281935014546035799989917015048182861857825663454

    p = int_nth_root(N, 2)
    assert p**2 == N

    phi = p*(p-1)
    d = pow(e, -1, phi)
    flag = pow(c, d, N)
    print(long_to_bytes(flag))
```

- Flag: `kurenaifCTF{phi_is_not_p-1_p-1}`

## redundant_rsa

次のようなスクリプトとその実行結果をくれる。

```python
from Crypto.Util.number import *
from flag import *
import secrets


leftDummy = secrets.token_bytes((500 - bytes_to_long(flag).bit_length()) // 8 // 2)
rightDummy = secrets.token_bytes((500 - bytes_to_long(flag).bit_length()) // 8 // 2)

# format: RANDOM_DATAkurenaifCTF{*}RANDOM_DATA
# please Extract kurenaifCTF{*} by manual work :)
m = bytes_to_long(leftDummy + flag + rightDummy)


p = getPrime(256)
q = getPrime(256)
N = p*q

# guarantee and hint 
assert GCD(m*m % N, N) == 1
assert GCD(m*m*m % N, N) == 1

# In CTF, 3 is sometimes used, but in general RSA, 65537 is used.
print("N =", N)
print("c3 =", pow(m, 3, N))
print("c65537 =", pow(m, 65537, N))

```

同一法で指数が異なるのでCommon Modulus Attackが使える。使用コードは次の通り(またしても自作ライブラリを使っています)

```python
from xcrypto import ext_euclid
from Crypto.Util.number import long_to_bytes


def common_modulous_attack(c1, c2, e1, e2, n):
    s1, s2, g = ext_euclid(e1, e2)
    _c1 = pow(c1, s1, n)
    _c2 = pow(c2, s2, n)

    return _c1 * _c2 % n


if __name__ == "__main__":
    N = 8208175638972200577186038102634114258848486365767463332763957381946985480397227219800325703361508208728778216773973313756762762324416016301819271949512427
    c3 = 510199524103978915755062119293765889950938959100085136114101960072728304594090942964306874023123457091885387418124063977610496306587745044542739034336862
    c65537 = 4673531855283872496727093452348048121242854682829577660566947295656149440028839210065857595110277181842297946378296819272562912619683355333762343087859186

    res = common_modulous_attack(c3, c65537, 3, 65537, N)
    flag = long_to_bytes(res)

    print(flag)
```

- Flag: `kurenaifCTF{you_4re_redundant_master}`

## the_big_five

次のようなスクリプトとその実行結果をくれる

```python
import os
import math
import binascii
import random
from Crypto.Util.number import *
from Crypto.Cipher import AES
from flag import *

class MyLCG:
    def __init__(self, S):
        self.A = int(binascii.hexlify(os.urandom(16)), 16)
        self.B = int(binascii.hexlify(os.urandom(16)), 16)
        self.M = getPrime(16*8)

        self.x = (S % self.M)
    def next(self):
        self.x = ((self.A * self.x) + self.B) % self.M
        return self.x

r = MyLCG(int(binascii.hexlify(os.urandom(16)), 16))
# print("A = " + str(r.A))
# print("B = " + str(r.B))
# print("M = " + str(r.M))
print("# M is prime number!")

cnt = 5
for i in range(cnt):
    print("X[{}] = {}".format(i,r.next()))

print("X[{}] = ?".format(cnt))

key = r.next()
cipher = AES.new(long_to_bytes(key), AES.MODE_CTR)
nonce = cipher.nonce
ct_bytes = cipher.encrypt(flag)
print("nonce = ", nonce)
print("ct_bytes = ", ct_bytes)

# decrypt
# cipher_dec = AES.new(long_to_bytes(key), AES.MODE_CTR, nonce=nonce)
# print(cipher_dec.decrypt(ct_bytes))

```

線形合同法で生成された乱数の内、連続した5つが与えられる。使われているパラメータの内、法である`M`が素数であるという情報だけが与えられている。添付されている`README.md`にある[動画リンク](https://youtu.be/DVZnJG76wdg)によれば、連続した6つの乱数があれば復元可能だが、5つしか与えられない。

この方法は{{katex(body="x_{i+1} = a*x_{i} + b \bmod m")}}である事から{{katex(body="x_{i+1} - x_i = a(x_{i} - x_{i-1})")}}となるので、{{katex(body="y_i := x_{i+1} - x_i")}}と定義すると{{katex(body="y_{i+1} = ay_i")}}になる。したがって、{{katex(body="y_i = a^iy_0")}}になる。よって{{katex(body="y_iy_j = a^{i+j}y_0^2")}}である事から、{{katex(body="i+j = i' + j'")}}となる添字の組で{{katex(body="i \neq i' \land j \neq j'")}}となるものを用意し、{{katex(body="y_iy_j - y_{i'}y_{j'}")}}を計算すると{{katex(body="M")}}を法として0になる、つまり{{katex(body="M")}}の倍数になるはずなので、そのようなものを複数用意して最大公約数を取り、それを素数になるまで割っていけば{{katex(body="M")}}が導出されるはずである。

前述の動画リンクではこれを6つの乱数で行っていたが、5つでも大して変わらない。{{katex(body="i+j=4")}}を{{katex(body="(i, j) = (1, 3), (2, 2)")}}で用意し、{{katex(body="i+j=5")}}を{{katex(body="(1, 4), (2, 3)")}}で用意した。

他のパラメータの求め方は前述のリンクにもある上に簡単な計算で完結するので省略する。

使用したコードは次の通り(例によって自作ライブラリを使っています)

```python
from xcrypto.num_util import list_gcd
from Crypto.Util.number import *
from Crypto.Cipher import AES


def next_lcg(a, b, m, x):
    return (a * x + b) % m


# x_2 = (a * x_1 + b(unknown)) % b
def solve_only_b(a, x_1, x_2, m):
    return (x_2 - a * x_1) % m


def solve_a_and_b(x_1, x_2, x_3, m):
    y_2 = (x_3 - x_2) % m
    y_1 = (x_2 - x_1) % m

    a = (pow(y_1, -1, m) * y_2) % m
    b = solve_only_b(a, x_1, x_2, m)

    return (a, b)


# todo: stricter solver
def solve_a_b_m(x_list):
    y = []
    for i in range(4):
        y.append(x_list[i + 1] - x_list[i])

    z = []
    z.append(y[0] * y[2] - y[1] * y[1])
    z.append(y[0] * y[3] - y[1] * y[2])

    g = list_gcd(z)
    while g % 2 == 0:
        g //= 2

    a, b = solve_a_and_b(x_list[1], x_list[2], x_list[3], g)

    return (a, b, g)

if __name__ == "__main__":
    x_list = [
        171988490999968958074461906163126253991,
        149759767375550138601832127658924300851,
        21392649857558566532141954695914673807,
        52236160143411890255640980579270361316,
        22081153611165744867415455406756477578,
    ]

    a, b, m = solve_a_b_m(x_list)

    print(a, b, m)
    for i in range(4):
        assert (a*x_list[i] + b) % m == x_list[i+1]
        pass

    x_5 = (a*x_list[-1] + b) % m

    nonce = b'\x0b:\xce<\xb0\xe8@,'
    cipher = AES.new(long_to_bytes(x_5), AES.MODE_CTR, nonce=nonce)
    ct_bytes =  b'\\\x8f\xfayc\xce\xfc<`\xc7\xe1\x91Jh\x0c6 \x8a\xd8\x0f\xdc^\xa3\xb9\xa1Kv\x96O<\xbcx\x8e\xea\xc3&'

    flag = cipher.decrypt(ct_bytes)

    print(flag)
```

- Flag: `kurenaifCTF{Less_numbers_are_better}`

## the_onetime_pad

次のようなスクリプトと実行結果が与えられる。

```python
import secrets
from flag import *
from Crypto.Util.number import *

class LCG:
    def __init__(self):
        self._x = secrets.randbits(64)
        self._a = 2
        self._m = secrets.randbits(64)

        while self._m % 2 == 0:
            self._m = secrets.randbits(64)

        print("m =", self._m)
    
    def next(self):
        self._x = (self._x*self._a) % self._m
        return self._x

lcg = LCG()

assert b"kurenaifCTF" in flag
flag = bytes_to_long(flag)


length = flag.bit_length()
print("length =", length)

rand = 0
for i in range(length + 50):
    rand += (lcg.next() & 1) << i

print("cipher =", rand ^ flag)

```

またしても線形合同法が登場する。`rand`変数の上位50bitは`flag`が寄与しないため判明し、おそらくフラグの先頭は`kurenaifCTF`だろうということで線形合同法で生成された乱数列の内、後半の50+87=137個の"最下位bit"は判明する。

ひとまず、ここで使われた乱数列の1つでも判明すればそれより後は生成手順を辿れば判明し、それより前は`a=2`の逆数を掛けていけば判明する。今回は、既にLSBが判明している乱数列の1つ前の乱数を特定する事を目標にする。

### 失敗した解法1: LLL

詳しい事は省くが線形合同法で生成された乱数のMSBが判明している場合、LLLを上手く使うと復元する事が出来る。が、今回はLSBが判明している上に1bitしか情報をくれない。色々と試行錯誤してみたが、流石のLLLでもこれは無理だった。

### 失敗した解法2: 乱数列の先頭の数を上位bitから確定させていく

この問題の乱数生成は{{katex(body="x_{i+1} = 2x_{i} \bmod m")}}である。これに注目すると、もし{{katex(body="2x_{i}")}}が{{katex(body="m")}}より小さければ偶数(最下位bitが0)でそうでなければ{{katex(body="m \leq 2x_i \lt 2m")}}より、{{katex(body="x_{i+1} = 2x_i - m")}}であり、{{katex(body="m")}}が奇数より、{{katex(body="x_{i+1}")}}も奇数(最下位bitが1)になる。

ここで、ある推定値{{katex(body="x+\alpha")}}を用意して乱数生成手順を経ていくと、次の値は{{katex(body="M")}}との大小関係だけで決定されるので、実際の値に近ければ似たような乱数列になり、先程の性質からLSBも似たような並びになると思われる。

したがって目標である乱数(64bit)の内、上から16bitずつ確定させていけば解けそうな気がしたのでそういうスクリプトを書いた。が、局所最適解に陥ったのか正しい値は得られなかった。

### 成功した解法: z3

SMTソルバであるz3は値の大小関係を条件に追加する事が出来るので先程述べた性質をそのまま条件として流し込んだら解いてくれた。あとはその値より前に生成された乱数を復元してそれぞれLSBを取っていく事で`rand`が復元出来るので`cipher`とXORを取ってフラグの残りの部分を復元する。

使用コードは次の通り

```python
import secrets
from Crypto.Util.number import *
import z3


class LCG:
    def __init__(self, x):
        self._x = x
        self._a = 2
        self._m = 16411099384203967235

        while self._m % 2 == 0:
            self._m = secrets.randbits(64)

    def next(self):
        self._x = (self._x*self._a) % self._m
        return self._x

if __name__ == "__main__":
    known = b"kurenaifCTF"
    m = 16411099384203967235
    cipher = 258578933248047129070234127076818734931906736562394908260192233729045538766864090271939203007290696772322321

    unknown_bits = 224
    _cipher = cipher >> unknown_bits
    known_flag = bytes_to_long(known)

    known_stream = _cipher ^ known_flag

    bits = []
    for _ in range(311 + 50 - unknown_bits):
        bits.append(known_stream & 1)
        known_stream >>= 1

    solver = z3.Solver()

    x = z3.Int("x")
    symbol_x = x
    for b in bits:
        if b == 0:
            solver.add(2*x < m)
            x = 2*x
        else:
            solver.add(2*x >= m)
            x = 2*x - m

    is_sat = solver.check()
    if is_sat != z3.sat:
        print("ha?")
        exit()

    res = solver.model()[symbol_x].as_long()
    print(res)

    tmp_res = res
    # assertion
    for b in bits:
        tmp_res = 2*tmp_res % m
        _b = tmp_res & 1
        if _b != b:
            print("ha?")

    ns = [0 for _ in range(unknown_bits)]
    inv_2_m = pow(2, -1, m)
    for i in range(unknown_bits):
        ns[unknown_bits - i - 1] = res
        res = res * inv_2_m % m

    rand = 0
    for i in range(unknown_bits):
        rand += (ns[i] & 1) << i

    unknown = cipher & ((1 << unknown_bits) - 1)
    print(known + long_to_bytes(rand ^ unknown))
    print("Done")
```

- Flag: `kurenaifCTF{lowest_bit_oracle_is_funny}`
