+++
title = "Dragon CTF 2020 - Bit Flip 1"
date = 2020-11-25

[taxonomies]
tags = ["CTF", "Writeup", "Crypto", "PRNG"]
+++

先日開催されたDragon CTFに出てCryptoを1問だけ解いたのでそのWriteupを書きます。

<!-- more -->

## Writeup

### 配布ソースコード

(多少コメントを加えています)

```python
#!/usr/bin/python3

from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
import hashlib
import os
import base64
from gmpy2 import is_prime

FLAG = open("flag").read()
FLAG += (16 - (len(FLAG) % 16))*" "  # 空白を加えて16バイトに調整
FLAG = FLAG.encode()


class Rng:
  def __init__(self, seed):
    self.seed = seed
    self.generated = b""
    self.num = 0

  def more_bytes(self):
    self.generated += hashlib.sha256(self.seed).digest()
    self.seed = long_to_bytes(bytes_to_long(self.seed) + 1, 32)
    self.num += 256


  def getbits(self, num=64):
    while (self.num < num):
      self.more_bytes()
    x = bytes_to_long(self.generated)
    self.num -= num
    self.generated = b""
    if self.num > 0:
      self.generated = long_to_bytes(x >> num, self.num // 8)
    return x & ((1 << num) - 1)


class DiffieHellman:
  def gen_prime(self):
    prime = self.rng.getbits(512)
    iter = 0
    while not is_prime(prime):
      iter += 1
      prime = self.rng.getbits(512)
    print("Generated after", iter, "iterations")
    return prime

  def __init__(self, seed, prime=None):
    self.rng = Rng(seed)
    if prime is None:
      prime = self.gen_prime()

    self.prime = prime
    self.my_secret = self.rng.getbits()
    self.my_number = pow(5, self.my_secret, prime)
    self.shared = 1337

  def set_other(self, x):
    self.shared ^= pow(x, self.my_secret, self.prime)

# "頭に"ヌルバイトを付与
def pad32(x):
  return (b"\x00"*32+x)[-32:]

def xor32(a, b):
  return bytes(x^y for x, y in zip(pad32(a), pad32(b)))

def bit_flip(x):
  print("bit-flip str:")
  flip_str = base64.b64decode(input().strip())
  return xor32(flip_str, x)


alice_seed = os.urandom(16)

while 1:
  alice = DiffieHellman(bit_flip(alice_seed))
  bob = DiffieHellman(os.urandom(16), alice.prime)

  alice.set_other(bob.my_number)
  print("bob number", bob.my_number)
  bob.set_other(alice.my_number)
  iv = os.urandom(16)
  print(base64.b64encode(iv).decode())
  cipher = AES.new(long_to_bytes(alice.shared, 16)[:16], AES.MODE_CBC, IV=iv)
  enc_flag = cipher.encrypt(FLAG)
  print(base64.b64encode(enc_flag).decode())

```

独自実装されたPRNGを使ってaliceとbobがDH鍵共有をしており、そこで共有されたAES鍵でフラグを暗号化している。これを何度も行う事が出来る。

aliceとbobは素数は同じもの(aliceが生成したもの)を使う一方で秘密鍵である指数は異なる初期seedを与えられた乱数生成器によって生成されている。

aliceのseedは固定な値で、そこにこちら側で(base64を介して)指定したバイト列とXORされたものがaliceのseedとして使われる。

鍵共有を行う為には毎度素数を生成する必要があるが、乱数生成器は一度の呼び出しで素数が生成されるとは限らない。共有毎にこの生成機が呼ばれた回数-1が表示される。

### 攻撃方針

bobの公開鍵は判明するが、それ以外のパラメータはaliceの公開鍵や素数すら開示されない。一見絶望的な状況だが、aliceのseedのXORされる前の値である`alice_seed`が分かってしまえば生成された素数に加えて秘密鍵まで判明するため共有された値が判明する。よって`alice_seed`をなんとかして導出することを目標にする。

### 乱数生成器の動作

ここで使われてる乱数生成器は概ね次のような動作をする。

1. seedを与える
2. `get_bytes()`メソッドに欲しい乱数のbit数を与える。
3. seedのバイト表現をSHA-256に入力し、結果を`generated`メンバ(初期値は空バイト列)と結合する。
4. seedをインクリメントする
5. 要求されたbit数が`generated`より大きかったら3. 4. を繰り返す。
6. 生成されたら要求されたbit数分だけ値を返し、それに応じて`generated`も切り出す(256bitの倍数が指定されている場合は空になるっぽい)

この問題では素数生成の為に512bit, 秘密鍵の為に64bitの乱数がそれぞれ要求されている。素数を作ってから秘密鍵が作られる為、素数が作られた際のseedを`seed`とおくと次の関係が成り立つ(`||`は文字列結合)

```
p: SHA-256(seed) || SHA-256(seed + 1)
x: SHA-256(seed + 2) の部分列(8bytes)
```

### `alice_seed`の各bitを決定させる

`get_prime()`メソッドは素数が出てくるまで乱数生成器をぶん回す(一般的に素数の分布はそこまで狭くは無いが一発で出る程でもない)。よってあるseedを与えたとしても素数が生成された時のseedはそれより大きい値になることが期待できる。ここで次のような状況を考える。

```
SHA-256(seed_0)     || SHA-256(seed_0 + 1) <- 素数ではない
SHA-256(seed_0 + 2) || SHA-256(seed_0 + 3) <- 素数ではない
...
SHA-256(seed_0 + a) || SHA-256(seed_0 + a + 1) <- 素数
```

この時、最初に与えたseedが`seed_0`であっても`seed_0 + 2`であっても同じ素数を生成することがわかる。異なるのは生成までに`get_bytes()`を呼び出した回数であり、前者の場合に比べて後者の場合は1少なくなる。

このseedの差が2なら素数生成に要する回数の差は1になる事を利用してbitを特定する。

今回の方法はLSB(0bit目、とする)は完全に特定出来ないので下位1bit目からbitを確定させていく。次のような2つのseedを考える。

```
<unknown>(? )11111...1<LSB>
<unknown>(~?)00000...0<LSB>
```

特定させたいbitを`?`とし、それより下位がLSBを除いて1で埋まっているか0で埋まっているかの違いである。また、下のseedにおける`?`はXOR時に1を指定して反転させている。

`alice_seed`の`?`より下のbitがLSBを除いて全部確定していると仮定すると鍵共有前のXOR処理においてこのようなseedを構成する事は可能である。ここでまず上のseedを提出して乱数生成器を用意し素数を入手する。この時`n`回の呼び出しで素数が生成されたとする。

続いて下のseedで乱数生成器を用意し、素数を入手する。ここで先程の特徴を利用すると`?`を特定出来る。

仮に`?`が0だった場合、2つのseedは次のようになる。

```
<unknown>011111...1<LSB>
<unknown>100000...0<LSB>
```

上のseed + 2が下のseedと一致する事がわかる。つまり、下のseedで素数生成に要した回数は`n-1`になる。

一方で`?`が1の場合は上のseed + 2が下のseedより2以上大きくなる事が期待されるためこのような事は起こらない。

よってこの2つのseedを利用して素数を生成した際の試行回数の差で`?`を特定する事が出来る。

これを下位1bit目(自身より下位のbitsの仮定は不要)から行っていけば最終的に`alice_seed`全体を特定することが出来る。

これでLSB以外は特定出来たので手元でLSBが0, 1どちらになるかを検証する(2通りしか無いので両方試すのも良い)。こうして`alice_seed`が入手出来たので使われた素数とaliceの秘密鍵を手元で導出して、後はbobの公開鍵(`bob.my_number`)でDH鍵共有の流れを経ればAESの鍵が入手出来、`enc_flag`を復号すると無事にフラグが手に入る。

## Code

たまに事故って失敗します。

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
import hashlib
import os
import base64
# from gmpy2 import is_prime
from xcrypto import is_prime
from pwn import remote
import subprocess


class Rng:
    def __init__(self, seed):
        self.seed = seed
        self.generated = b""
        self.num = 0

    def more_bytes(self):
        self.generated += hashlib.sha256(self.seed).digest()
        self.seed = long_to_bytes(bytes_to_long(self.seed) + 1, 32)
        self.num += 256


    def getbits(self, num=64):
        while (self.num < num):
            self.more_bytes()
        x = bytes_to_long(self.generated)
        self.num -= num
        self.generated = b""
        if self.num > 0:
            self.generated = long_to_bytes(x >> num, self.num // 8)
        return x & ((1 << num) - 1)


class DiffieHellman:
    def gen_prime(self):
        # print(f"[+] seed: {bin(bytes_to_long(self.rng.seed))}")
        prime = self.rng.getbits(512)
        iter = 0
        while not is_prime(prime):
            iter += 1
            prime = self.rng.getbits(512)
        # print("Generated after", iter, "iterations")
        self.iter = iter
        return prime

    def __init__(self, seed, prime=None):
        self.rng = Rng(seed)
        if prime is None:
            prime = self.gen_prime()

        self.prime = prime
        self.my_secret = self.rng.getbits()
        self.my_number = pow(5, self.my_secret, prime)
        self.shared = 1337

    def set_other(self, x):
        self.shared ^= pow(x, self.my_secret, self.prime)

# "頭に"ヌルバイトを付与
def pad32(x):
    return (b"\x00"*32+x)[-32:]

def xor32(a, b):
    return bytes(x^y for x, y in zip(pad32(a), pad32(b)))

def bit_flip(x, flip_str):
    return xor32(flip_str, x)


def bits_to_bytes(bits_arr):
    bits_str = "".join(map(str, bits_arr))
    return long_to_bytes(int(bits_str, 2))


if __name__ == '__main__':
    # sc = remote("bitflip2.hackable.software", 1337)
    sc = remote("bitflip1.hackable.software", 1337)
    sc.recvuntil("Proof of Work: ")
    cmd = sc.recvline().decode().strip().split(" ")
    print(cmd)

    poc = subprocess.run(cmd, stdout=subprocess.PIPE).stdout
    print(poc)
    sc.sendline(poc.strip())

    pred_seed = [0 for _ in range(128)]
    first_iter = -1

    for i in range(1, 128):
        sc.recvuntil(b"bit-flip str:\n")
        flip = [0 for _ in range(128)]
        for j in range(1, i):
            flip[-j-1] = pred_seed[-j-1]^1

        sc.sendline(base64.b64encode(bits_to_bytes(flip)))

        sc.recvuntil(b"Generated after ")
        iter1 = int(sc.recvuntil(b" ").strip())
        if i == 1:
            first_iter = iter1

        for j in range(1, i):
            flip[-j-1] = pred_seed[-j-1]
        flip[-i-1] = 1

        sc.recvuntil(b"bit-flip str:\n")
        sc.sendline(base64.b64encode(bits_to_bytes(flip)))

        sc.recvuntil(b"Generated after ")
        iter2 = int(sc.recvuntil(b" ").strip())
        if iter2 == iter1 - 1:
            pred_seed[-i-1] = 0
        else:
            pred_seed[-i-1] = 1

        print(pred_seed[-i-1], iter1, iter2)

    print("[+] seed:", "".join(map(str,pred_seed)))

    pred_seed_1 = int("".join(map(str, pred_seed)), 2)

    alice = DiffieHellman(long_to_bytes(pred_seed_1))

    if alice.iter == first_iter:
        pred_seed = pred_seed_1
    else:
        pred_seed[-1] = 1
        pred_seed = int("".join(map(str, pred_seed)), 2)

    mal = DiffieHellman(long_to_bytes(pred_seed))

    sc.recvuntil(b"bit-flip str:\n")
    sc.sendline(base64.b64encode(b"\x00"))
    sc.recvuntil(b"bob number ")
    bob_n = int(sc.recvline().strip())

    share = pow(bob_n, mal.my_secret, mal.prime)
    iv = base64.b64decode(sc.recvline().strip())
    enc_flag = base64.b64decode(sc.recvline().strip())

    cipher = AES.new(long_to_bytes(share, 16)[:16], AES.MODE_CBC, IV=iv)

    print(cipher.decrypt(enc_flag))

```

## Flag

`DrgnS{T1min9_4ttack_f0r_k3y_generation}`
