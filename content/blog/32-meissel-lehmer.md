+++
title = "Meissel-Lehmerのアルゴリズム"
date = 2022-06-11

[taxonomies]
tags = ["algorithm", "prime_number"]
+++

## 序文

面白いアルゴリズムを探すために、最近教えてもらった[Library Checker](https://judge.yosupo.jp/)を眺めていたら[素数計数関数](https://ja.wikipedia.org/wiki/%E7%B4%A0%E6%95%B0%E8%A8%88%E6%95%B0%E9%96%A2%E6%95%B0) $\pi(x)$を$x$までの素数を列挙するより速く計算する方法があることが判明したので紹介します。

<!-- more -->

## Algorithm

特に断りが無ければ、$x$は実数とする。

以下では$a$番目の素数を$p_a$とおく。1-indexedなので$p_1 = 2$である。

自然数$a$に対して、次の関数$\phi(x,a)$を定義する。

$$
\phi(x,a) = |\\{n \leq x : \forall p \ (p \ \mathrm{is \ prime}) \ [p |n \Rightarrow p \gt p_a]\\}|
$$

これは$n$の素因数が「全て」$p_a$よりも大きいような$n$の個数を指している。例えば$\phi(10,2) = |\\{1,5,7\\}| = 3$である($a_2 = 3$より、これより大きい素因数からなる10以下の数は5,7のみである、1は素数の約数を持たないことから前提が偽となり満たされる)。直感的にはエラトステネスの篩において$p_a$で篩にかけた後に残った整数の数に相当する。

また、非負整数$k$と自然数$a$に対して、次の関数$P_k(x,a)$を定義する。

$$
P_k(x,a) = |\\{n \leq x : n = q_1q_2\cdots q_k \ (q_1,\dots, q_k \gt p_a)\\}|
$$

これはつまり、$p_a$より大きい素数をちょうど$k$個素因数に持つ数の総数である。なお、便宜上$P_0(x,a) = |\\{1\\}| = 1$とする。

自明な式として次がある

$$
\begin{aligned}
\phi(x,a) &= \sum_{k=0}^\infty P_k(x,a) \cr
P_1(x,a) &= \pi(x) - a
\end{aligned}
$$

よって、これを変形して次が導かれる。

$$
\pi(x) = \phi(x,a) + a - 1 - \sum_{k=2}^\infty P_k(x,a)
$$

ここでどんな$a$に対しても、$x \lt p_a^k$となる$k$が必ず存在することから、$P_k(x,a)$に対してある添字が存在して、それより大きい添字では$P_k(x,a) = 0$となるため、この無限和は有限の値をとる。特に$a = \pi(x^{\frac 1N})$とすれば、$P_k(x,a)$は$k\geq N$において0になる。

よって、$P_k(x,a), \phi(x,a)$の計算回数が少なくなるような$a$を選択すれば効率的に計算できることが期待される。$P_3(x,a)$まで計算するために$a = x^{\frac 14}$としていることが多いようなので下記実装例ではこの値を用いている。

なお、$a$を大きくすると非零な$P_k(x,a)$の数が少なくなる一方、$\phi(x,a)$は再帰的に計算するため(詳しくは後述)、$a$が大きいと計算回数が多くなることから極端に$a$を大きくしたり小さくしたりすれば良いわけではないようである(独自研究)。

### $P_k(x,a)$の計算

前述の通り、$k$は小さい値だけ計算すれば良いため、よく使われる$k=2,3$の場合のみを考える。

$P_2(x,a) = |\\{p_ip_j \mid p_a \lt p_i \leq p_j \land p_ip_j \leq x\\}|$であり、ここで使われている$p_i$は$p_a \lt p_i \leq \sqrt x$を満たす。ここで自然数$i \gt a$に対して次のような関数$P_2^{(i)}(x)$を定義する。

$$
P_2^{(i)}(x) = |\\{p_ip_j \mid p_i \leq p_j \land p_ip_j \leq x\\}|
$$

これを用いると$P_2(x,a)$は次のように表すことが出来る。

$$
P_2(x,a) = \sum_{i=a+1}^{\pi({\sqrt x})}P_2^{(i)}(x)
$$

$p_i \leq \sqrt x$であるから、$i$として取り得る添字は$\pi(\sqrt x)$が最大であることに注意する。

ここで、$p_i \leq p_j \land p_ip_j \leq x$を満たす$p_j$の数は$\pi\left({\frac{x}{p_i}}\right) - (i-1)$である。これは$p_ip_j \leq x$を満たす素数$p_j$の数が$\pi\left(\frac x{p_i}\right)$であり、そこから$p_i$未満の素数の数である$i-1$を引いたものになることから説明出来る。

以上より、$P_2(x,a)$は次のようになる。

$$
P_2(x,a) = \sum_{i=a+1}^{\pi({\sqrt x})} \left(\pi\left({\frac{x}{p_i}}\right) - (i-1)\right) = \sum_{i=a+1}^{\pi({\sqrt x})}\pi\left({\frac{x}{p_i}}\right) - \left(\frac{(\pi(\sqrt x) - 1)\pi(\sqrt x)}2 - \frac{(a-1)a}2 \right)
$$

$P_3(x,a)$についても同様に考える。

$p_ip_jp_l \leq x$となる3つの整数$p_i, p_j, p_l$がいずれも$p_a$より大きく、$p_a \lt p_i \leq p_j \leq p_l$とする。

この条件から$p_a \lt p_i \leq x^{\frac 13}$と$p_j \leq p_j \leq \sqrt{\frac{x}{p_i}}$が成り立つ。これが満たされている上で、条件を満たす$p_l$の数は、$P_2^{(i)}(x,a)$の場合と同様に考えると$\pi\left(\frac x{p_ip_j}\right) - (j-1)$個となる。

以上より、$P_3(x,a)$は次のようになる。

$$
P_3(x,a) = \sum_{i=a+1}^{\pi(x^{\frac 13})} \sum_{j=i}^{\pi(\sqrt{\frac {x}{p_i}})} \left(\pi\left(\frac x{p_ip_j}\right) - (j-1)\right)
$$

$P_2, P_3$のいずれにおいても$i$番目の素数$p_i$を計算しておく必要があるが、添字の最大が$\pi(\sqrt x)$であることから、こちらもエラトステネスの篩で$\sqrt x$までの素数を列挙しておけば良い。

また、関数$\pi$も使われているが、小さい$x$における$\pi(x)$は列挙した素数を二部探索することによって計算出来る。

### $\phi(x,a)$の計算

$\phi(x,a)$は次のような再帰関数になる。

$$
\phi(x,a) = \phi(x,a-1) - \phi\left(\frac x{p_a}, a-1\right)
$$

この関数は最終的に$a=1$の場合に辿り着くが、これは$x$以下の奇数の数に相当するので計算することが出来る。

これは次のようにして導出される。

まず、$\delta(x,a) \coloneqq \phi(x,a-1) - \phi(x,a)$とおく。これはエラトステネスの篩において$p_a$で落される数を表している。よって落とされる数の集合は$\\{p_ak\mid k \in \mathbb N \land p_ak \leq x\\}$の「部分集合」(既に落された数字を除いたもの)になる。$k$の範囲についてはもう少し詳細に書くと$1 \leq k \leq \left\lfloor \frac x{p_a}\right\rfloor$となり、この中から$p_a$より前の篩で落とされなかった数の数が$\delta(x,a)$に相当する。

$p_a$以前の篩で落とされた数は$k$が$p_a$未満の素数を素因数として含んでいるものになる。よって一方の「$p_a$より小さい素数で落とされなかった」数は$k$がこれらを素因数として含んでいないものになり、このような$k$の総数は$\phi\left(\left\lfloor\frac{x}{p_a}\right\rfloor, a-1\right)$となる。したがって、このような$k$と同じ数だけ$p_a$で落とされることになり、$\delta(x,a) =\phi\left(\left\lfloor\frac{x}{p_a}\right\rfloor, a-1\right)$が導かれる。

## 実装

```python
from bisect import bisect
from math import isqrt, ceil
from typing import List
import sys
sys.setrecursionlimit(10**6)


def create_sieve(n: int) -> List[bool]:
    sieve = [True for _ in range(n + 1)]
    sieve[0] = False
    sieve[1] = False
    for i in range(2, isqrt(n) + 1):
        if not sieve[i]:
            continue

        for j in range(i**2, n+1, i):
            sieve[j] = False

    return sieve


def get_primes(n: int) -> List[int]:
    sieve = create_sieve(n)
    ret = []
    for i, res in enumerate(sieve):
        if res:
            ret.append(i)

    return ret


limit = 10**6
primes = get_primes(limit)
pi_cache = {}
phi_cache = {}

def get_prime(i: int) -> int:
    if i < 1 or i > len(primes):
        raise ValueError

    return primes[i-1]


def small_pi(x: int) -> int:
    if x in pi_cache:
        return pi_cache[x]

    if x > limit:
        raise ValueError

    i = bisect(primes, x)
    pi_cache[x] = i

    return i


def pi(x: int) -> int:
    if x in pi_cache:
        return pi_cache[x]

    if x <= limit:
        return small_pi(x)

    a = pi(int(x ** (1/4)))
    phi_xa = phi(x, a)
    p2_xa = p2(x, a)
    p3_xa = p3(x, a)

    ret = phi_xa + a - 1 - p2_xa - p3_xa

    pi_cache[x] = ret

    return ret


def phi(x: int, a: int) -> int:
    if (x, a) in phi_cache:
        return phi_cache[(x, a)]

    if a == 1:
        return (x + 1) // 2

    if x < 1:
        return 0

    ret = phi(x, a - 1) - phi(x // get_prime(a), a - 1)
    phi_cache[(x, a)] = ret

    return ret


def p2(x: int, a: int) -> int:
    ret = 0
    pi_sqrt_x = pi(isqrt(x))
    for i in range(a+1, pi_sqrt_x+1):
        ret += pi(x // get_prime(i))

    return ret - (pi_sqrt_x - 1) * pi_sqrt_x // 2 + (a - 1) * a // 2


def p3(x: int, a: int) -> int:
    ret = 0
    pi_croot_x = pi(int(x**(1/3)))

    for i in range(a+1, pi_croot_x + 1):
        p_i = get_prime(i)
        for j in range(i, pi(isqrt(x // p_i)) + 1):
            p_j = get_prime(j)
            ret += pi(x // p_i // p_j) - (j - 1)

    return ret

N = 10**11
print(pi(N))  # 4118054813
```

## References

- [Meissel–Lehmer algorithm - Wikipedia](https://en.wikipedia.org/wiki/Meissel%E2%80%93Lehmer_algorithm)
- [acganesh - Efficient Prime Counting with the Meissel-Lehmer Algorithm](https://web.archive.org/web/20201214032848/https://acgan.sh/posts/2016-12-23-prime-counting.html): 元サイトがFirefoxに警告吐かれたのでInternet Archive
