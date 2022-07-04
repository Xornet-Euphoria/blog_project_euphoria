+++
title = "Google CTF 2022 - Maybe Someday"
date = 2022-07-05

[taxonomies]
tags = ["CTF", "Writeup", "Crypto", "Paillier"]
+++

- 問題ファイル: <https://github.com/google/google-ctf/blob/master/2022/crypto-maybe-someday/challenge/chall.py>

## Prerequisite

- Paillier暗号の加法準同型性

## Writeup

次のようなスクリプトが動いている

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

from Crypto.Util.number import getPrime as get_prime
import math
import random
import os
import hashlib

# Suppose gcd(p, q) = 1. Find x such that
#   1. 0 <= x < p * q, and
#   2. x = a (mod p), and
#   3. x = b (mod q).
def crt(a, b, p, q):
    return (a*pow(q, -1, p)*q + b*pow(p, -1, q)*p) % (p*q)

def L(x, n):
    return (x-1) // n

class Paillier:
    def __init__(self):
        p = get_prime(1024)
        q = get_prime(1024)

        n = p * q
        λ = (p-1) * (q-1) // math.gcd(p-1, q-1) # lcm(p-1, q-1)
        g = random.randint(0, n-1)
        µ = pow(L(pow(g, λ, n**2), n), -1, n)

        self.n = n
        self.λ = λ
        self.g = g
        self.µ = µ

        self.p = p
        self.q = q

    # https://www.rfc-editor.org/rfc/rfc3447#section-7.2.1
    def pad(self, m):
        padding_size = 2048//8 - 3 - len(m)
        
        if padding_size < 8:
            raise Exception('message too long')

        random_padding = b'\0' * padding_size
        while b'\0' in random_padding:
            random_padding = os.urandom(padding_size)

        return b'\x00\x02' + random_padding + b'\x00' + m

    def unpad(self, m):
        if m[:2] != b'\x00\x02':
            raise Exception('decryption error')

        random_padding, m = m[2:].split(b'\x00', 1)

        if len(random_padding) < 8:
            raise Exception('decryption error')

        return m

    def public_key(self):
        return (self.n, self.g)

    def secret_key(self):
        return (self.λ, self.µ)

    def encrypt(self, m):
        g = self.g
        n = self.n

        m = self.pad(m)
        m = int.from_bytes(m, 'big')

        r = random.randint(0, n-1)
        c = pow(g, m, n**2) * pow(r, n, n**2) % n**2

        return c

    def decrypt(self, c):
        λ = self.λ
        µ = self.µ
        n = self.n

        m = L(pow(c, λ, n**2), n) * µ % n
        m = m.to_bytes(2048//8, 'big')

        return self.unpad(m)

    def fast_decrypt(self, c):
        λ = self.λ
        µ = self.µ
        n = self.n
        p = self.p
        q = self.q

        rp = pow(c, λ, p**2)
        rq = pow(c, λ, q**2)
        r = crt(rp, rq, p**2, q**2)
        m = L(r, n) * µ % n
        m = m.to_bytes(2048//8, 'big')

        return self.unpad(m)

def challenge(p):
    secret = os.urandom(2)
    secret = hashlib.sha512(secret).hexdigest().encode()
    print(f"secret = {secret.decode()}")

    c0 = p.encrypt(secret)
    print(f'{c0 = }')

    # # The secret has 16 bits of entropy.
    # # Hence 16 oracle calls should be sufficient, isn't it?
    # for _ in range(16):
    #     c = int(input())
    #     try:
    #         p.decrypt(c)
    #         print('😀')
    #     except:
    #         print('😡')

    # I decided to make it non-interactive to make this harder.
    # Good news: I'll give you 25% more oracle calls to compensate, anyways.
    cs = [int(input()) for _ in range(20)]
    for c in cs:
        try:
            p.fast_decrypt(c)
            print('😀')
        except:
            print('😡')

    guess = input().encode()

    if guess != secret: raise Exception('incorrect guess!')

def main():
    with open('./flag.txt', 'r') as f:  # original: /flag.txt
      flag = f.read()

    p = Paillier()
    n, g = p.public_key()
    print(f'{n = }')
    print(f'{g = }')

    try:
        # Once is happenstance. Twice is coincidence...
        # Sixteen times is a recovery of the pseudorandom number generator.
        for _ in range(16):
            challenge(p)
            print('💡')
        print(f'🏁 {flag}')
    except:
        print('👋')

if __name__ == '__main__':
    main()

```

(多分普通の)Paillier暗号が実装されている。しかもplaintextなCryptosystemでは無く、平文`m`に対して次のようなパディングが施されて平文`m'`として暗号化される。

`m' := b"\x00\x02" + padding + b"\x00" + m`

ここで、パディング部分と平文を`b"\x00"`で区切って区別するために、`padding`には`b"\x00"`が含まれない。

このパディングによって復号結果に次のようなチェックが存在し、もし違反している場合は例外が発生する。

1. 復号結果の先頭が`b"\x00\x02"`であるかどうか
2. `padding`部分が8バイト以上あるかどうか

このCryptosystemを用いて次のようなチャレンジに16回成功する必要がある

1. 2バイトの秘密`secret`が用意され、それをSHA-512でハッシュ化した結果`sha512(secret).hexdigest().encode()`を平文として暗号化される(この暗号文は`c0`として与えられる)
2. 20個の暗号文を「一度に」入力してから復号する
3. 復号時のチェックにおいて例外が発生したかどうかを20個の暗号文それぞれについて結果が教えられる
4. その結果を元に`secret`が何であったかを当てる

---

この問題を解くのに必要なポイントは次の3つである

1. Paillier暗号の加法準同型性
2. 平文が`sha512(secret).hexdigest().encode()`であり、`.hexdigest()`によって16進数の文字列に変換される
3. `unpad`時、`b"\x00"`が存在していないと例外が発生する

1については有名な話で、Paillier暗号には世にも珍しい加法準同型性が存在する。2つの平文$m_1, m_2$に対する暗号文を$c_1, c_2$とおくと、$c_i \equiv g^{m_i}r_i^n \mod n^2$となる(ここで、$g,n$が公開鍵である)。よって、$c_1c_2 \equiv g^{m_1+m_2}(r_1r_2)^n \mod n$となるから、$c_1c_2$は$m_1+m_2$を平文とした暗号文になる。

よって、`c0`を受け取った後に、別の暗号文を用意しておけば、それを掛けることで復号結果をある程度改変する事が出来る。例えばパディングと平文を分ける`b"\x00"`の位置に何かしらのバイトを加える別の平文を暗号化した結果を用意しておけば、この`b"\x00"`を潰す事が出来る。

2については平文が`b"0123456789abcdef"`から構成されることになり、使われる文字種が少なくなることが利用できる。

3については`unpad`における次の部分が該当する。

```python
random_padding, m = m[2:].split(b'\x00', 1)
```

右辺が2つ以上の要素になるとは限らず、もし1つだけなら代入が失敗して次のようにエラーが吐かれる

```python
>>> x, y = "a b c".split("x",1)
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
ValueError: not enough values to unpack (expected 2, got 1)
>>> 
```

したがって、`unpad`の成功可否には上記の2つの条件に加えて`b"\x00"`によって2つ以上に分割されるか、つまりそもそも「`b"\x00"`が復号結果に存在するか」という条件も含まれることになる。

新しいオラクルを利用するために、加法準同型性を用いてパディングと平文を分ける`b"\x00"`を潰した平文を用意する。

```
secret: \x00\x02 ...(padding) \x00 ...(plaintext)
add_pt:                       \xfe \x00\x00...
```

これで`secret`を暗号化した結果`c0`と`add_pt`を暗号化した結果`c'`に対して`c0 * c1 mod n^2`は`secret`と`add_pt`を数値として足した結果の暗号文となる。これをこのまま送っても`\x00`が無くなったことで復号オラクルは「復号失敗」という自明な結果を返すのみである。

復号が成功するような結果を返すには、`secret`の`plaintext`部分にある数値を足して`\x00`を出現させる必要がある。平文の各バイトは`b"0123456789abcdef"`のみからなるので、`\x30`から`\x39`と`\x61`から`\x66`に限られる。よって、例えば`\x30`であるバイトに`\xd0`を足すような平文を用意すればそのバイトは`0x30+0xd0 = 0x100`となって、繰り上がってバイトが`\x00`になる。

よって、このような平文を用意して、手元で暗号化し、`c0`に掛けてオラクルに送り込むことで、`secret`の指定したインデックスにおけるバイトが、こちらから指定したなんらかのバイトと一致するかどうかを判定することが出来る。先程の例では`\xd0`を入れたインデックスが`\x30`(つまり`b"0"`)かどうかを判定出来る。

ただし1バイトずつやっていくのでは情報量が少なく、20個の暗号文では間に合わない。さらにオラクルに送る暗号文は一度に与えなくてはならないのでもう少し工夫する必要がある。

`secret`が取りうる値はハッシュ化前のバイトがたったの2バイトなので65536通りに過ぎず、もし1回のオラクルで半分に絞ることが出来れば、20回のオラクルで絞り込める候補の期待値は$\frac{65536}{2^{20}} \leq 1$となり、十分判定出来るものと思われる。よって、このようなオラクルを考える。

前述のどこかのバイトに関する情報を得る方法は1バイトのみの例だったが、これは単に該当するインデックスのバイトで加算をしているだけなので、他のインデックスでも同時に出来る。よって、複数のインデックスに対して同時に判定出来る。

バイトはたったの16種類しか存在しないので、ある1バイトがなんらかのバイトである確率は$1/16$となる。よって、そのバイトがそうでない確率は$15/16$となるので、$n$個のインデックスに対してそれら全てがそのバイトで無い確率は$(15/16)^n$となる。したがって、$(15/16)^n \sim 1/2$となるような$n$を用いてオラクルとすれば1回のオラクルの度に`secret`の候補を半分ずつ絞ることが出来て、最終的に候補数が1になる事が期待出来る。$n=11$を用いた。

注意点として、加法準同型性を利用して、`secret`に対して値を足す時に、繰り上がりが発生して隣接するバイトに影響を及ぼすことから判定に用いるインデックスは隣り合わないようにする必要がある。

あくまで確率的なアルゴリズムなのでたまに候補を1つに絞りきれないことがあるが、運が良ければそこから1つ選べば当たる。そんな感じで祈りながらソルバを回したらフラグが出た。

## Code

```python
from Crypto.Util.number import getPrime as get_prime
import math
import random
import os
import hashlib
from pwn import remote, process
import sys


def crt(a, b, p, q):
    return (a*pow(q, -1, p)*q + b*pow(p, -1, q)*p) % (p*q)

def L(x, n):
    return (x-1) // n

class Encrypter:
    def __init__(self, n, g):
        self.n = n
        self.g = g

    # https://www.rfc-editor.org/rfc/rfc3447#section-7.2.1
    def pad(self, m):
        padding_size = 2048//8 - 3 - len(m)
        
        if padding_size < 8:
            raise Exception('message too long')

        random_padding = b'\0' * padding_size
        while b'\0' in random_padding:
            random_padding = os.urandom(padding_size)

        return b'\x00\x02' + random_padding + b'\x00' + m

    def unpad(self, m):
        if m[:2] != b'\x00\x02':
            raise Exception('decryption error')

        random_padding, m = m[2:].split(b'\x00', 1)

        if len(random_padding) < 8:
            raise Exception('decryption error')

        return m

    def encrypt(self, m):
        g = self.g
        n = self.n

        m = int.from_bytes(m, 'big')

        r = random.randint(0, n-1)
        c = pow(g, m, n**2) * pow(r, n, n**2) % n**2

        return c


def get_random_idx(l, n):
    ret = []
    for _ in range(n):
        while True:
            c = random.randint(0, l-1)
            if c not in ret and c - 1 not in ret and c + 1 not in ret:
                break
        ret.append(c)

    return ret


def construct_pt(b, idxes) -> bytes:
    pt = [0 for _ in range(128)]
    for i in idxes:
        pt[i] = b

    return bytes(pt)


def create_new_pt(b):
    idxes = get_random_idx(128, 11)
    pt = construct_pt(b, idxes)

    return pt, idxes


hash_table = {}

for x in range(256**2):
    secret = x.to_bytes(2, "big")
    hash_secret = hashlib.sha512(secret).hexdigest().encode()
    hash_table[hash_secret] = secret

def check_hash(h, constraints, reses, verbose=False):
    for (b, idxes), res in zip(constraints, reses):
        target = bytes([h[i] for i in idxes])
        if verbose:
            print(res, h, target, idxes)
        if res:
            if b.to_bytes(1, "big") not in target:
                return False
        else:
            if b.to_bytes(1, "big") in target:
                return False

    return True


oracle_bytes = {}

for c in b"0123456789abcdef":
    b = 0x100 - c
    oracle_bytes[c] = b


# ==============================================================

DEBUG = "-d" in sys.argv

if DEBUG:
    sc = process(["python3", "chall.py"])
else:
    # sc = process(["python3", "org_chall.py"])
    sc = remote("maybe-someday.2022.ctfcompetition.com", 1337)

sc.recvuntil(b"n = ")
n = int(sc.recvline())
sc.recvuntil(b"g = ")
g = int(sc.recvline())

cipher = Encrypter(n, g)
pt_length = 128
pad = b"\xfe" + b"\x00" * pt_length

for round in range(16):
    s = None
    if DEBUG:
        sc.recvuntil(b"secret = ")
        s = sc.recvline().strip()
        print(f"{s = }, {hash_table[s]}")
    sc.recvuntil(b"c0 = ")
    c0 = int(sc.recvline())
    constraints = []
    for _c, b in oracle_bytes.items():
        c = c0
        pad_c = cipher.encrypt(pad)
        c = c0 * pad_c % (n**2)
        # byte_c = cipher.encrypt(b.to_bytes(1, "little") + b"\x00" * (pt_length - 1))
        new_pt, idxes = create_new_pt(b)
        byte_c = cipher.encrypt(new_pt)
        c = c * byte_c % (n**2)
        sc.sendline(str(c).encode())
        constraints.append((_c, idxes))

    cnt = 0
    for _c, b in oracle_bytes.items():
        c = c0
        pad_c = cipher.encrypt(pad)
        c = c0 * pad_c % (n**2)
        # byte_c = cipher.encrypt(b.to_bytes(1, "little") + b"\x00" * (pt_length - 1))
        new_pt, idxes = create_new_pt(b)
        byte_c = cipher.encrypt(new_pt)
        c = c * byte_c % (n**2)
        sc.sendline(str(c).encode())
        constraints.append((_c, idxes))
        cnt += 1
        if cnt == 4:
            break

    res = []
    for i in range(20):
        res.append(sc.recvline().decode().strip() == "😀")
        # print(res[i], constraints[i])

    cands = []

    for h in hash_table:
        if check_hash(h, constraints, res):
            cands.append(h)

    if DEBUG:
        assert s in cands

    if len(cands) > 1:
        print("[!] Warning: 2 or more candidates are found")
    elif len(cands) == 0:
        print("[!] not found...")
        exit()

    sc.sendline(cands[0])
    res = sc.recvline().decode().strip()
    if res == '💡':
        print(f"{round}: ok")
    else:
        print(f"{round}: shit")
        exit()

sc.interactive()

```

## Flag

`CTF{p4dd1n9_or4cl3_w1th_h0mom0rph1c_pr0p3r7y_c0m6in3d_in7o_a_w31rd_m47h_puzz1e}`
