+++
title = "Berlekamp-Welchのアルゴリズム"
date = 2022-06-04

[taxonomies]
tags = ["algorithm", "coding_theory"]
+++

## 序文

LFSRの勉強をしていた際に、Berlekamp-Messeyのアルゴリズムが出てきたのでそれ関連でリードソロモン符号について調べてみたら、結構凄さを感じたアルゴリズムだったので紹介します。

<!-- more -->

## 問題設定

次のような符号化を考える(最初に考案されたリードソロモン符号)。

0. メッセージ長を$m$、符号長を$n$とする。なお、許容される符号の誤りは$\frac{n - m - 1}2$個までとなる
1. 各バイトやパケットを有限体$\mathbb F_p$の要素に変換して、それを係数とする$\mathbb F_p$上の$m-1$次多項式$f(x)$を作る
2. 長さ$n$の符号を次のように生成する
	1. $c_i = f(a_i)$
	2. ここで$a_i$は$i \neq j$なら互いに異なる$\mathbb F_p$の要素であり、送信者と受信者で共有されている

この符号$C = (f(a_1), f(a_2), \dots, f(a_n))$に対して誤りが前述の$\frac{n-m-1}2$個であればそれを訂正出来るアルゴリズム(Berlekamp-Welch Algorithm)が存在する[^1]。以降、この数を$k$とおく($k\coloneqq \frac{n-m-1}2$)

アルゴリズムの大まかな流れは$q(x) = e(x)f(x)$となるような多項式$q(x), e(x)$を求め、$\frac{q(x)}{e(x)}$を計算して$f(x)$を求めるという形になる。

## アルゴリズム

- input: 受信した($k$以下の誤りを含む)符号 $(y_1, y_2, \dots, y_n)$
- output: $f(x)$

アルゴリズム本体の前に前節の最後で触れた$g(x), e(x)$に対し、$e(x)$が何であるかについて示す。これは$y_i \neq f(a_i)$であるような$y_i$を解に持つ多項式であり、次のような形になる。

$$
\begin{aligned}
E &\coloneqq \\{a_i \mid y_i \neq f(a_i)\\} \cr
e(x) &\coloneqq \prod_{i \in E} (x - a_i)
\end{aligned}
$$

この$e(x)$を用いると任意の$i$に対して次が成り立つ。

$$
e(a_i)f(a_i) = e(a_i)y_i
$$

誤りがない、つまり$y_i = f(a_i)$の時に成り立つのは自明であり、そうでない場合も$e(a_i) = 0$となることからこの等式が成り立つ。ここで多項式$q(x) \coloneqq e(x)f(x)$を定義すれば、当然$q(a_i) - e(a_i)y_i = 0$が任意の$i$で成り立つ。

ここで、$q(x)$と$e(x)$は未知であるが、その係数を変数とした連立方程式を考えるとこれは線形方程式となる。$e(x)$はその構成から$k$次のモニック方程式であるので、既知の係数(1)である先頭を除いて、未知の係数は高々$k$個となる。また、$q(x)$の次数は定義から$k+m$次となるので未知の係数は$k+m+1$個ある。よって全体で$2k+m+1$個の未知変数が存在する線形方程式を解くので、これより多くの$a_i$が必要であり、したがって、$n \geq 2k+m+1$である。

$e(x), q(x)$について次のように定義する。

$$
\begin{aligned}
e(x) \coloneqq \sum_{j=0}^k e_jx^j\cr
q(x) \coloneqq \sum_{j=0}^{k+m} q_jx^j
\end{aligned}
$$

これを用いると任意の$i$に対して次が成り立つ。

$$
q_0 + q_1a_i + q_2a_i^2 + \dots + q_{k+m}a_i^{k+m} - y_i(e_0 + e_1a_i + e_2a_i^2 + \dots + e_{k-1}a_i^{k-1} + a_i^k) = 0
$$

$e$の$k$次の係数は1であることから、この式には$-y_ia_i^k$という既知の項が存在する。よってこれを右辺に持っていくことで次の等式が成り立つ。

$$
q_0 + q_1a_i + q_2a_i^2 + \dots + q_{k+m}a_i^{k+m} - y_i(e_0 + e_1a_i + e_2a_i^2 + \dots + e_{k-1}a_i^{k-1}) = y_ia_i^k
$$

未知数である$e_j, q_j$は線形の項しか存在しないので、全ての$i$に対するこの等式は次のような行列で表すことが出来る。

$$
\begin{pmatrix}
1 & a_1 & a_1^2 &\dots& a_1^{k+m} & -y_1 & -y_1a_1 & -y_1a_1^2 & \dots & y_1a_1^{k-1} \cr
1 & a_2 & a_2^2 &\dots& a_2^{k+m} & -y_2 & -y_2a_2 & -y_2a_2^2 & \dots & y_2a_2^{k-1} \cr
&&&&&\vdots \cr
1 & a_n & a_n^2 &\dots& a_n^{k+m} & -y_n & -y_na_n & -y_na_n^2 & \dots & y_na_n^{k-1} \cr
\end{pmatrix} \begin{pmatrix}
q_0 \cr q_1 \cr q_2 \cr \vdots \cr q_{k+m} \cr
e_0 \cr e_1 \cr e_2 \cr \vdots \cr e_{k-1}
\end{pmatrix} = \begin{pmatrix}
y_1a_1^k \cr y_2 a_2^k \cr \vdots \cr y_na_n^k
\end{pmatrix}
$$

これが解ければ、$e(x)$と$q(x)$が手に入るので$q(x)$を$e(x)$で割って、$f(x)$が手に入る。

## 実装(SageMath)

```python
K = GF(521)
PR.<x> = PolynomialRing(K)

m = 5
coeffs = [K.random_element() for _ in range(m)]
f = PR(coeffs)
k = 3
n = 2*k+m+1

A = [i+1 for i in range(n)]
code = [f(a) for a in A]

for _ in range(k):
    i = randint(0, 11)
    code[i] = K.random_element()

M = []
v = []
for i in range(n):
    row_left = [K(A[i])^e for e in range(k+m+1)]
    row_right = [-code[i] * K(A[i])^e for e in range(k)]
    row = row_left + row_right

    v.append(code[i]*K(A[i])^k)

    M.append(row)

M = matrix(K, M)
v = vector(K, v)
polys = M.solve_right(v)

q = PR(list(polys[:k+m+1]))
e = PR(list(polys[k+m+1:]) + [1])

assert q / e == f
```

## References

- [Berlekamp–Welch algorithm - Wikipedia](https://en.wikipedia.org/wiki/Berlekamp%E2%80%93Welch_algorithm)
- [Reed–Solomon error correction - Wikipedia](https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction)
- [The Berlekamp-Welch Algorithm: A Guide](https://gfeng2001.github.io/assets/pdfs/cs70/BWGuide.pdf)
- <https://www.jaist.ac.jp/~fujisaki/2020/I486S-2020-0602.pdf>: Shamirの秘密分散に応用する例、日本語

---

[^1]: ちなみに誤りが無いならラグランジュ補間で$f(x)$を復元出来る
