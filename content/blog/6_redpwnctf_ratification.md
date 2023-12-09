+++
title = "redpwnCTF 2020 - ratification"
date = 2020-11-27

[taxonomies]
tags = ["CTF", "Writeup", "Crypto", "RSA"]
+++

今年の6月に開催されたredpwnCTFで解けなかったCrypto問題であるratificationの復習をようやく終えたのでそのWriteupになります。

<!-- more -->

## Writeup

### Outline

通常とは異なり、$N$ではなく$p$が与えられているRSA署名で、署名だけでなくアルゴリズム中で使われている一部のパラメータも与えられている。

この内`a`で定義されているパラメータはbit数が小さい事を利用して導出出来る。そしてこの値を利用すると、もう1つの素数である$q$に対して$q-1$を法とした合同式が手に入り、これは$q$以外の値が既知である式なので$q-1$の倍数を生成することが出来る。

この署名は(フラグ開示用のメッセージでなければ)何度でも署名が出来、その度に$p, q$は固定だが`a`は異なる為、毎回異なった$q-1$の倍数を生成することが出来る。これを利用して最大公約数を$q$が素数になってかつbit数も合うようになるまで取っていけば$q$を求めることが出来るので、これを利用してフラグ開示用のメッセージの署名を手元で作る事ができる。

### 配布ソースコード

```python
#!/usr/bin/env python3
import numpy as np
from Crypto.Util.number import *
from random import randint

flag = open('flag.txt','rb').read()

p = getPrime(1024)
q = getPrime(1024)
n = p*q
e = 65537

message = bytes_to_long(b'redpwnCTF is a cybersecurity competition hosted by the redpwn CTF team.')

def menu():
    print()
    print('[1] Sign')
    print('[2] Verify')
    print('[3] Exit')
    return input()

print(p)

while True:
    choice = menu()

    if choice == '1':
        msg = bytes_to_long(input('Message: ').encode())
        if msg == message:
            print('Invalid message!')
            continue

        n1 = [randint(0,11) for _ in range(29)]
        n2 = [randint(0,2**(max(p.bit_length(),q.bit_length())-11)-1) for _ in range(29)]
        a = sum(n1[i]*n2[i] for i in range(29))

        enc = [pow(msg,i,n) for i in n2]
        P = np.prod(list(map(lambda x,y: pow(x,y,p),enc,n1)))
        Q = np.prod(list(map(lambda x,y: pow(x,y,q),enc,n1)))
        b = inverse(e,(p-1)*(q-1))-a
        sig1 = b%(p-1)+randint(0,q-2)*(p-1)
        sig2 = b%(q-1)+randint(0,p-2)*(q-1)
        print(sig1,sig2)

        sp = pow(msg,sig1,n)*P%p
        sq = pow(msg,sig2,n)*Q%q
        s = (q*inverse(q,p)*sp + p*inverse(p,q)*sq) % n

        print(s)
        print("Signed!")

        b_p = sig1 % (p-1)
        d_p = inverse(e, (p-1))
        a_p = (d_p - b_p) % (p-1)
        print(a_p)
        print(a)

    elif choice == '2':
        try:
            msg = bytes_to_long(input('Message: ').encode())
            sig = int(input('Signature: '))
            if pow(sig,e,n) == msg:
                print("Verified!")
                if msg == message:
                    print("Here's your flag: {}".format(flag))
            else:
                print("ERROR HAS OCCURRED...")
        except:
            print("Invalid signature!")

    elif choice == '3':
        print("Good bye!")
        break
```

よくある署名問題同様、任意のメッセージを署名出来て、フラグを開示する為のメッセージ(ここでは`'redpwnCTF is a cybersecurity competition hosted by the redpwn CTF team.'`)とその署名を提出するとフラグをくれる。当然このメッセージを署名する事は出来ない。

普通の署名であれば公開鍵である$N$をくれるのだがここでは何故かその素因数の片割れである$p$をくれる。指数公開鍵である$e$もくれる。

### 使われている変数の解析

まず`n1, n2, enc`であるがこれらは乱数列である。`n1`の各要素は高々11までで`n2`の各要素は$2^{1013} - 1$までである。`enc`は`enc[i] = pow(msg, n2[i], n)`となる数列である。

`a`は一旦飛ばして`P, Q`を観察すると、`_p[i] = pow(enc[i], n1[i], p)`, `_q[i] = pow(enc[i], n[i], q)`となる`_p, _q`の総積が`P, Q`になる。先程の`enc`と併せて式にすると次のようになる。

$$
P : \equiv \prod_i {enc}_i^{n1_i} \equiv \prod_i {{msg}^{n1_i+n2_i}} \equiv msg^{\sum_i n1_in2_i} \bmod p
$$

$$
Q : \equiv \prod_i {enc}_i^{n1_i} \equiv \prod_i {{msg}^{n1_i+n2_i}} \equiv msg^{\sum_i n1_in2_i} \bmod q
$$

なお、`enc`は$N$を法とした値なのに`P, Q`の計算では$p$を法とした値として良いのかという疑問が浮かぶかもしれないが

$$
x \equiv y \bmod (pq) \Rightarrow \exist k \in \mathbb{Z} \ (x-y = kpq) \Rightarrow x \equiv y \bmod p
$$

これが成り立つので特に問題は無い。以後断り無くこれを適用する場面が存在する。

ここで先程飛ばした`a`に注目すると

$$
a = \sum_i n1_in2_i
$$

であるので、$P, Q$に代入すると次のようになる。

$$
P = msg^a \bmod p
$$

$$
Q = msg^a \bmod q
$$

続いて登場するのは`b`だが、これは単純で

$$
e(a + b) \equiv 1 \bmod (p-1)(q-1)
$$

となる`b`を生成している。そしてこの`b`を用いて`sig1, sig2`を生成している。これらに関して次のような関係がある。

$$
sig1 \equiv b \bmod (p-1)
$$

$$
sig2 \equiv b \bmod (q-1)
$$

続いて`sp, sq`が出現するがそれぞれ最終的に`p, q`で法を取っているので`pow(msg, sig1, n)`の`n`は`p`にしても問題無い。`P`や`sq`に関しても同様でこれを利用すると次のようになる。

$$
sp :\equiv msg^{sig1}msg^{a} \equiv msg^{a+b} \bmod p
$$

$$
sq :\equiv msg^{sig1}msg^{a} \equiv msg^{a+b} \bmod q
$$

ここで先程の`sig1, sig2`が$p-1, q-1$に関して`b`と合同であるという事実を用いた(フェルマーの小定理)。

そして最後に署名である`s`が計算される。`s % p, s % q`をそれぞれ計算すると`s % p = q*inverse(q, p)*sp % p`, `s % q = p*inverse(p, q)*sq % q`になる。ここである整数`k, l`を用いて`q*inverse(q, p) = kp+1, p*inverse(p, q) = lq+1`とおくことが出来るので最終的に`q*inverse(q, p)*sp % p = sp % p = pow(msg, a+b, p)`, `p*inverse(p, q)*sq % q = sq % q = pow(msg, a+b, q)`になる。

これより`s, p, q`に関して整数$k_1, k_2$を用いて次のような関係が成り立つ

$$
s = k_1 p + msg^{a+b} = k_2q + msg^{a+b}
$$

右の等式が成り立つ為には$k_1p = k_2q$でなくてはならず、$p, q$は互いに素なので$k_1$は$q$を、$k_2$は$p$をそれぞれ素因数として含む。

したがって$s = kN + msg^{a+b}$となるような整数$k$が存在する事から

$$
s \equiv msg^{a+b} \bmod N
$$

である。$(a+b)e \equiv 1 \bmod (p-1)(q-1)$であることから、$s^e \equiv msg \bmod N$である(オイラーの定理)。よって最終的にRSA署名を生成している事がわかる。

### `a`のbit数

ここで`a`のbit数を見積もってみると`n1, n2`の各要素はそれぞれ4, 1013bit以下であることから`n1[i]*n2[i]`の各要素は大きくても1017bitである。これが29個あり、その総和が`a`であるので`a`は大きくても1022bitに収まることがわかる。

一方$p, q$のbit数は1024bitである事から`a`は明らかにこれらより小さい。よって$p-1, q-1$を法とする式に`a`が出現し、そこから`a`と合同な値を求める事が出来た場合はこれに一致する。

ここで$e(a+b) \equiv 1 \bmod (p-1)(q-1)$の関係があり、この法を$p-1$に下げると

$$
a \equiv 1/e - b \bmod (p-1)
$$

である。$p-1$を法として$b$と合同な値は`sig1`であることを既に示しているのでこれを使って`a = (pow(e, -1, p-1) - sig1) % (p-1)`と求めることが出来る。

### `q-1`の抽出

一方で$q-1$を法とした時の`a`はどうなるかを考える。$b \equiv sig2 \bmod (q-1)$であることから$(a + sig2)e \equiv 1 \bmod (q-1)$

が成り立つのでこれを変形して

$$
\exists k \in \mathbb{Z} \ ((a + sig2)e - 1 = k(q - 1))
$$

が成り立つ。故に`(a + sig2) * e - 1`が$q-1$の倍数になる。

ここで署名毎に`a, sig2`が変わる一方で$q$は変わらないので署名毎に異なる$q-1$の倍数を手に入れることが出来る。ということは幾つかこの値を手に入れて最大公約数を取っていけばいつか$q-1$が手に入るはずである(下記ソースコード中では5回で試しているが殆どの場合で手に入った)。

### フラグ開示メッセージ署名の作成

これで$q$が手に入ったので目標としてるメッセージのRSA署名を手元で作成することが出来る。これをメッセージと共に提出するとフラグが手に入る。

## Code

```python
from pwn import remote
from Crypto.Util.number import isPrime, long_to_bytes, bytes_to_long
from xcrypto import list_gcd
from xcrypto.prime import is_prime


if __name__ == '__main__':
    target = "localhost"
    port = 13337


    e = 65537
    sc = remote(target, port)
    p = int(sc.recvline().rstrip())

    print("[+] p:", p)
    print(p.bit_length())
    assert isPrime(p)

    target_msg = b'redpwnCTF is a cybersecurity competition hosted by the redpwn CTF team.'
    target_n = bytes_to_long(target_msg)

    q_g = []
    for _ in range(5):
        sc.sendline("1")

        sc.recvuntil(b"Message: ")
        msg = b"\x02"
        sc.sendline(msg)

        sig1, sig2 = map(int, sc.recvline().split(b" "))

        print("[+] sig1", sig1)
        print("[+] sig2", sig2)

        a = pow(e, -1, p-1) - (sig1 % (p-1))
        print("[+] a:", a)
        print(a.bit_length())

        s = int(sc.recvline())
        print("[+] s:", s)

        q_g.append((a + sig2)*e - 1)

        sc.recvuntil("Signed!\n")

    q = list_gcd(q_g) + 1
    print("[+] q:", q)
    assert is_prime(q)

    n = p*q
    d = pow(e, -1, (p-1)*(q-1))
    sig = pow(bytes_to_long(target_msg), d, n)

    sc.sendline("2")
    sc.recvuntil(b"Message: ")
    sc.sendline(target_msg)
    sc.recvuntil(b"Signature: ")
    sc.sendline(str(sig))
    sc.recvuntil(b"flag: ")
    flag = sc.recvline().strip().decode()

    print(f"[+] flag: {flag}")

    sc.close()

```

## Flag

`flag{random_flags_are_secure-2504b7e69c65676367aef1d9658821030011f8968a640b504d320846ab5d5029b}`

## リンク, 参考にしたWriteup

- 問題リンク: <https://github.com/redpwn/redpwnctf-2020-challenges/tree/master/crypto/ratification>
- `a`が導出出来る事を知ったWriteup: <https://dunsp4rce.github.io/redpwn-2020/crypto/2020/06/27/ratification.html>
- `sig1, sig2`を使わない非想定解: <https://priv.pub/posts/redpwnctf-2020/>
