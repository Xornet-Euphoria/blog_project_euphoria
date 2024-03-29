+++
title = "Coppersmith's Attackを再実装する"
date = 2022-05-20

[taxonomies]
tags = ["CTF", "Crypto", "Coppersmith's Attack", "Lattice"]
+++

## 序文

模範的なCryptoプレイヤーなので、突如Coppersmith's Attackを実装していない事に恐れを抱いてしまった。というわけで再実装をする。

<!-- more -->

本音を言えば、元の原理を知っていれば多変数や法の約数を法とした場合などへの応用がしやすくなるんじゃないかと思ったので取り組み始めた次第である。

更に本音を重ねると、その最中に見つけたわかりやすい資料の知名度が他のCryptoやCTF関連資料に比べて妙に低いと思ったのでそれを紹介することも兼ねている、というかこちらが最大の目的である。車輪の再発明をしただけのこんな記事を読んでないで一番下までスクロールして参考資料をクリックしてダウンロードしてタブを閉じましょう。

---

冗談はさておき、今回は$\mathbb Z/n\mathbb Z$上の単変数モニック多項式の小さい根を求めるアルゴリズムをSageMathで実装する。


## Prerequisites

- 格子基底簡約
	- LLLで十分だが、Coppersmith's Attackで求められる解の限界を評価するためにはLLLで求められる最も小さい基底のノルムの上界を知っておく必要がある

## Outline

アルゴリズムと実装の解説に入る前にアルゴリズムの概観を説明する。

まず前提となるのは、ある多項式$f$が$f(x_0) \equiv 0 \mod n$となる時、$f$の定数倍: $af(x)$や他の多項式を掛けたもの: $f(x)h(x)$、同じ根$x_0$を持つ多項式$g(x)$ (すなわち、$g(x_0) \equiv 0 \mod n$)との和: $f(x) + g(x)$もまた$x_0$を根として持つという事実である。

これによって、$f$を起点として同じ根を持つ多項式を複数用意することが出来る。そして、それらの整数係数の線形結合も$x_0$を根として持つことから、線形結合によって作られた多項式の中で係数の絶対値が小さくなるようなものを用意する。ここで基底簡約が使われる。

これで得られた多項式は係数が小さいことから、それに値を代入した結果も小さくなることが期待出来る。そして、もしその多項式に$x_0$を代入した結果の絶対値が$n$より小さければ、その多項式を$f_0$とおくと$f_0(x_0) = 0$となるはずである (法を取らずとも0である)。

法が無い場合の方程式は様々な方法によって簡単に解けるので、それで解けば$x_0$が得られる。

以上がCoppersmith's Attackの大まかな説明である。

## Howgrave-Graham's Lemma

前節では最終的に法がなくとも同じ根を持つような多項式を構成することを言ったが、具体的にそういう方程式はどのような条件で実現できるのかを考える。これに対する答えがHowgrave-Graham's Lemmaであり次である。

$n$を法とした$e$次多項式$f(x)$に対して、ある数$X$が存在し、$f$の根$x_0$について$|x_0| \lt X$であると仮定する (つまり、$X$が$|x_0|$の上界である)。

この時、次が成立するなら$f(x_0) = 0$である。

$$
\|f(xX)\| \lt \frac n{\sqrt {e+1}}
$$

ここで、多項式$f(x) = \sum_{i=0}^e a_ix^i$に対するノルム$\|f(x)\|$を次で定義する。

$$
\|f(x)\| = \sqrt{\sum_{i=0}^e a_i^2}
$$

証明は次のようになる。

まず次の不等式が成り立つ。

$$
|f(x_0)| \leq \sum_{i=0}^e |a_ix_0^i| \leq \sum_{i=0}^e |a_i|X^i
$$

ここで最左辺はベクトル$(|a_0|, |a_1|X, \dots, |a_e|X^e)$と1が$e+1$個並んだベクトル$(1,1,\dots,1)$の内積で表される。

ベクトルの内積はノルムの積以下であるという事実を用いて次が成り立つ。

$$
\begin{aligned}
\sum_{i=0}^e|a_i|X^i &= \langle (|a_0|, |a_1|X, \dots, |a_e|X^e), (1,1,\dots,1)\rangle\cr 
&\leq \|(|a_0|, |a_1|X, \dots, |a_e|X^e)\|\|(1,1,\dots,1)\|\cr
&=\|f(xX)\|\sqrt{e+1}
\end{aligned}
$$

ここで$\|f(xX)\| \lt \frac n{\sqrt {e+1}}$を仮定しているので、最終的に次の不等式が得られる。

$$
\begin{aligned}
|f(x_0)| &\leq \sum_{i=0}^e|a_i|X^i \cr
&\leq \|f(xX)\|\sqrt{e+1}\cr
&\lt \frac{n}{\sqrt{e+1}}\sqrt{e+1} \cr
&= n
\end{aligned}
$$

この不等式より、$-n \lt f(x_0) \lt n$が得られるが、$f(x_0) \equiv 0 \mod n$であったから、$f(x_0) = nk$となる何らかの整数$k$が存在する。このような$k$は不等式より$k=0$しかあり得ず、したがって$f(x_0) = 0$となる。$\Box$

## 他の多項式を集める

Howgrave-Graham's Lemma(以下、「補題」とする)より目的とする多項式の条件が判明した。続いての目標はこのような多項式の構成であり、そのために同じ根を持つ多項式の線形結合を用いる。

無闇矢鱈と多項式の線形結合(スカラー倍や多項式同士の和)を繰り返していても意味が無く、後述するようにこれはLLLのような格子の基底簡約アルゴリズムが上手くやってくれる。そこでここでは線形結合に使えそうな別の多項式を集めることを考える。

$f(x)$に対して、$f(x)^2$もまた$x_0$を根として持つが、ノルムが大きくなってしまうのであまり意味が無い。結局候補となるのは次のような式である。

$$
\begin{aligned}
f_0(x) &\coloneqq n\cr
f_1(x) &\coloneqq nx\cr
&\vdots\cr
f_{e-1}(x) &\coloneqq nx^{e-1}\cr
f_e(x) & \coloneqq f(x)
\end{aligned}
$$

これらは全て$x_0$を根として持つことから、基底として使えそうである。

また、これより更に良い結果を得る方法が存在する。補題の右辺を見直して見ると$\frac n{\sqrt{e+1}}$が多項式のノルムの上界となっており、$n$に対して$O(n)$の大きさであるが、$n^2$を法として根が$x_0$である多項式を用意することで、これを$O(n^2)$にすることが出来る。

もちろん、そのような多項式は、先程棄却した$f(x)^2$のようなものとなり、ノルムも大きくなる。補題の左辺の$x$の係数が単純計算で$n$と同じく2乗程度の増加を見せ、$e^2$の次数においてはその係数が$(X^e)^2$となり、多項式のノルムもこのぐらいになるが、$|x_0|$が$n$に対して有意に小さいことから、$X$も小さくとることが出来る。よって、右辺の2乗による増加は左辺の2乗による増加に比べてかなり大きくなることから、より有利な条件となる。

では、実際に$n^2$を法として$x_0$を根に持つ多項式を用意してみる。次のような多項式$f_{i,j} \ (0\leq i \leq 2)$は$n^2$を法として根$x_0$を持つ。

$$
f_{i,j}(x) = n^{2-i}x^jf(x)^i
$$

$f(x_0) = nk$となる整数$k$が存在するから、$f(x)^i =n^ik^i$となり、$n^{2-i}f(x_0)^i =n^2k^i \equiv 0 \mod n^2$となるから、$f_{i,j}(x_0) \equiv 0 \mod n^2$である。

同様にして$n^3, n^4,\dots$のように法を大きくしていくと、それを法として$x_0$が根となる複数の多項式が得られる。

## 格子基底簡約

前節で多項式が得られたので、これがHowgrave-Graham's Lemmaを適用出来るぐらい小さくする。これには(この節のタイトル通り)格子基底簡約を用いる。目標は次のようなベクトルを基底として持つような格子行列の導出である。

$$
\boldsymbol c = (c_0, c_1X, \dots, c_eX^e)
$$

当然だが、各$c_i$に対して$g(x) \coloneqq \sum_{i=0}^e c_ix^i$として$g(x_0) \equiv 0 \mod n$となるような簡約を行う。

この時、$\boldsymbol c$のノルムは、$\|g(xX)\|$に等しいことが定義からわかる。基底を簡約していることから、$\boldsymbol c$のノルムは小さくなっていることが期待され、補題の条件を満たす程度になっていれば$x_0$を求めることが出来る。

では肝心の簡約する基底はどうするかというと次のようにする。

まず$f(x)$に対して、ある整数$m \geq 1$を用意し、前節のように、$f_{i,j}(x) \coloneqq n^{m-i}x^jf(x)^i$を$0 \leq i \leq m, 0 \leq j \leq e-1$の範囲で用意する。この時、$\deg {f_{i,j}} = j + ei$となることから、$i,j$が異なれば$f_{i,j}$の次数も異なる。また、$\deg f_{i,j}$の最大値は$em+e-1$となる。$0 \leq k \leq em+e-1$となる整数$k$に対して、$\deg f_{i,j} = k$となる$f_{i,j}$が一意的に存在することから、多項式は$em+e-1+1 = e(m+1)$本得られることになる。以後、$d\coloneqq e(m+1)$とおく。

ここで多項式$f_{i,j}(xX)$を計算し、その係数を成分にとる次のような行列$M$を作る。但し、$f^{(k)}\_{i,j}(x)$で、多項式$f_{i,j}(x)$の$k$次の係数を指すものとする。また、括弧内は$xX$であり、$X$は変数ではないことから、$X$のべきが係数に掛けられる事にも注意する。

$$
M_{i,j} = f_{k,l}^{(j)}(xX) \ \ \ (\deg f_{k,l}(xX) = l+ek = i)
$$

すなわち、$i$行目の成分は次数が$i$である$f_{k,l}(xX)$の係数が順に並ぶ。$e=3, m=3$で例を構成してみる。この場合は$d = e(m+1)=12$となるから12本の多項式が得られる。

$f_{i,j}(x)$は次のようになる。

|$i,j$|$\deg{f_{i,j}}$|$f_{i,j}$|
|----|----|----|
|0,0|0|$n^3$|
|0,1|1|$n^3x$|
|0,2|2|$n^3x^2$|
|1,0|3|$n^2f(x)$|
|1,1|4|$n^2xf(x)$|
|1,2|5|$n^2x^2f(x)$|
|2,0|6|$nf(x)^2$|
|2,1|7|$nxf(x)^2$|
|2,2|8|$nx^2f(x)^2$|
|3,0|9|$f(x)^3$|
|3,1|10|$xf(x)^3$|
|3,2|11|$x^2f(x)^3$|

よって、行列$M$は対角成分にのみ注目すると、次のようになる。$f(x)$がモニック多項式であることから、$f_{i,j}(x)$もモニック多項式であり、$f_{i,j}(xX)$の最高次数に$X$のべきが現れることに注意する。

$$
\begin{pmatrix}
n^3 \cr
 & n^3X \cr
 & & n^3X^2 \cr
 & & & n^2X^3 \cr
 & & & & n^2X^4 \cr
 & & & & & n^2X^5 \cr
 & & & & & & nX^6 \cr
 & & & & & & & nX^7 \cr
 & & & & & & & & nX^8 \cr
 & & & & & & & & & X^9 \cr
 & & & & & & & & & & X^{10} \cr
 & & & & & & & & & & & X^{11} \cr
\end{pmatrix}
$$

この行列の左下には各$f_{i,j}(xX)$の他の次数における係数が並んでいる。また、$j$列目の成分は$f_{k,l}(xX)$の$j$次係数であるから、$X^j$と$f_{k,l}(x)$の$j$次係数の積となり、$CX^j$となんらかの整数$C$を用いて表される。

一方、右上は全て0である下三角行列である。よって、行列式は対角成分の積となる (この後の基底簡約の評価で用いる)。

この基底行列に左から係数ベクトル$(a_0, a_1,\dots, a_{d-1}) \in \mathbb Z^d$を掛けると$(b_0, b_1X, \dots, b_{d-1}X^{d-1})$が現れる。これらの関係は次のようになっている。

$$
b_iX^i = \sum_{j=0}^{d-1} a_jf^{(i)}_{k,l}(xX) \ \ \ (\deg f\_{k,l} = l+ke = j)
$$

したがって、$b_iX$は$f_{k,l}(xX)$の整数係数の線形結合で出来た多項式から$i$次の係数を取り出したものになる。

以上より多項式$h(xX) = \sum_{i=0}^{d-1}b_iX^ix^i$とおくと、$h(x) = \sum_{i=0}^{d-1}b_ix^i$であり、更に$\|h(xX)\| = \|(b_0, b_1X, \dots, b_{d-1}X^{d-1})\|$である。

また、次が成り立つ。

$$
h(xX) = \sum_{i=0}^{d-1}a_if_{k,l}(xX) \ \ \ (\deg f_{k,l} = l+ke = i)
$$

ここで$xX = x_0$を代入すると、$h(x_0) \equiv 0 \mod n^m$となる。よって$M$が張る格子に含まれるベクトルから、$h$のように多項式を構成すれば$x_0$が根となる多項式を得ることが出来る。

目的としていたのは、ノルムが小さい多項式であったから、$h$の$i$次係数$b_i$を小さくすると考えるのが自然である。そこで格子基底簡約が登場する。

基底簡約のアルゴリズムには色々あるが、今回は昨今のCTFプレイヤーに人気なLLLを用いる (ついでに解の上界である$X$の評価も楽になる)。$M$をLLL簡約して出てきたベクトルを$\boldsymbol b \coloneqq (b_0, b_1X, \dots, b_{d-1}X^d)$とおく。


既に示しているように$\boldsymbol b$から多項式$h$を構成すると、$\|h(xX)\| = \|\boldsymbol b\|$であるから、Howgrave-Graham's Lemmaの仮定を満たすには次が成り立つ必要がある。

$$
\|\boldsymbol b\| \leq \frac{n^m}{\sqrt d}
$$

右辺がこのようになるのは、法を$n$から$n^m$にしており、得ている多項式の最大次数が$em + e - 1$であることに注意する。

よって、$M$を簡約して出てきたベクトルがこれを満たしているなら、根である$r_0$を求めることが出来る。次の節でこの不等式を満たすような$X$、つまり解の上界が何であるかを評価する。

## $X$の条件

先に述べたように、$M$は下三角行列であるから行列式はその対角成分の積になる。この構成から$|M|$を計算すると次のようになる。

$$
|M| = n^{\left(\sum_{i=0}^m i\cdot e\right)}X^{\left(\sum_{i=0}^{d-1}i\right)} = n^{\frac{m(m+1)}2e} X^{\frac{d(d-1)}2} = n^{\frac {md}2} X^{\frac{d(d-1)}2}
$$

計算を簡単にするため、LLLの簡約パラメータ$\delta$を$\delta = \frac 34$とすると$M$をLLL簡約した時の最も短いベクトルの大きさは$2^{\frac{d-1}4}|M|^\frac 1d$以下になるため、次が成り立つ。

$$
\|\boldsymbol b\| \leq 2^{\frac{d-1}4}|M|^{\frac 1d} = 2^{\frac{d-1}4} n^{\frac m2} X^{\frac {d-1}2}
$$

この式から、$\|\boldsymbol b\|$の上界はわかっているので、それがこの式の右辺より小さいような場合を考える。したがって次のような不等式を満たすような$X$を考えることになる。

$$
2^{\frac{d-1}4} n^{\frac m2} X^{\frac {d-1}2} \leq \frac{n^m}{\sqrt d}
$$

これを満たすような$X$であればHowgrave-Graham's Lemmaから$x_0$を求めることが出来る。

$X$だけの不等式にするために、両辺$\frac{2}{d-1}$乗して移項すると次のようになる。

$$
X \leq \frac{n^{\frac{m}{d-1}}}{d^{\frac 1{d-1}}}\cdot 2^{-\frac 12} = \frac 1{\sqrt 2}\cdot \frac{n^{\frac{m}{d-1}}}{d^{\frac 1{d-1}}}
$$

ここで、$\frac{m}{d-1}$に関して次の不等式が成り立つ。

$$
\frac{m}{d-1} \gt \frac{m}d = \frac{m}{e(m+1)} = \frac{1}{e} - \frac{1}{e(m+1)} \gt \frac 1e - \frac 1m
$$

よって、$n$の指数として次が成り立つ。

$$
n^{\frac 1e - \frac 1m} \leq n^{\frac{m}{d-1}}
$$

また、$d^{\frac 1{d-1}}$に関して次の不等式が成り立つ。

$$
d^{\frac 1{d-1}} \leq d \Leftrightarrow \frac 1d \leq \frac 1{d^{\frac 1{d-1}}}
$$

よって次の不等式が成り立つ。

$$
\frac 1{\sqrt 2}\frac{n^{\frac 1e - \frac 1m}}{d} \leq \frac 1{\sqrt 2}\frac{n^{\frac{m}{d-1}}}{d^{\frac 1{d-1}}}
$$

したがって、もし左辺が$X$より大きかったら、右辺も大きくなる。式にすると次のようになる。

$$
X \leq \frac 1{\sqrt 2}\frac{n^{\frac 1e - \frac 1m}}{d} \Rightarrow X \leq \frac 1{\sqrt 2} \frac{n^{\frac{m}{d-1}}}{d^{\frac 1{d-1}}}
$$

右側の不等式を満たしているならHowgrave-Graham's Lemmaの仮定も満たしていることになるので、$x_0$を求めることが出来るような$X$の条件は$X \leq \frac 1{\sqrt 2}\frac{n^{\frac 1e - \frac 1m}}{d}$である。

## 実装

$m$と$X$は指定する必要がある。

```python
def solve(f, m, X):
    e = f.degree()
    d = e*(m+1)
    n = f.base_ring().order()
    f = f.change_ring(ZZ)
    var = f.variables()[0]
    coeffs = f.coefficients()

    fs = []
    for _d in range(d):
        i,j = _d // e, _d % e
        _f = n^(m-i) * var^j * f^i
        fs.append(_f(var*X))

    M = []
    for _f in fs:
        _coeffs = _f.coefficients(sparse=False)
        _coeffs += [0 for _ in range(d - len(_coeffs))]
        M.append(_coeffs)

    M = matrix(ZZ, M)

    PRZ.<r> = PolynomialRing(ZZ)
    B = M.LLL()

    ret = set()
    for b in B:
        b = [_b // X^i for i, _b in enumerate(b)]
        h = PRZ(b)
        rs = h.roots()
        if len(rs) > 0:
            for _r, _ in rs:
                if _r < 0:
                    _r += n
                if f(_r) % n == 0:
                    ret.add(_r)

    return tuple(ret)


# test
n = 45649
PR.<x> = PolynomialRing(Zmod(n))

# x = 4
ans = 4
f = x^2 + 113*x + 45181

roots = solve(f, m=3, X=200)

# check
assert ans in roots
for r in roots:
    assert f(r) == 0
```

## 余談1: `small_roots()`との対応

SageMathに実装されているCoppersmith's Attackは`small_roots()`という名前だが、これの引数はある程度今回使ったものに対応している。

よく使うのは`epsilon`, `X`, `beta`であるが、`beta`以外は次のような対応になっている。

- `epislon`: $\frac 1m$に対応する。よって、上記実装で$m$を指定するのは`epislon=1/m`としているのと同じである
- `X`: (明らかだが)$X$に対応する

## 余談2: $n$の約数を法とする場合

Coppersmith's AttackのVariantとして、未知の$n$の約数を法とした場合の合同方程式も解くことが出来るというのがあるが、これは通常のCoppersmith's Attackで多項式に$n$を掛けるところを$n$の約数に変えているだけである。と言っても、$n$の約数は未知なので直接掛けるのではなく$n$を掛けて代用している。

そのせいで格子の体積が大きくなり、簡約しても出てくる基底のノルムが大きくなってしまう。よって、上記の$X$の評価はそのまま使う事は出来ない。一般のRSA同様$n = pq$で$p\approx q \approx n^{1/2}$として、$p$を法とした合同方程式を解くのなら、解の大きさは$n^{1/4}$未満である必要がある。

気が向いたら解の大きさについての評価を書きます。

## Resources

- [katagaitai workshop winter - elliptic-shiho's labs](http://elliptic-shiho.github.io/slide/katagaitai_winter_2018.pdf)
  - 日本語で一番わかりやすいCoppersmith's Attackの資料、この資料(と付随する参考文献)を読めば私のこの記事は不要
- [現代暗号への招待 - 株式会社サイエンス社 株式会社新世社 株式会社数理工学社](https://www.saiensu.co.jp/search/?isbn=978-4-7819-1262-2&y=2010)
  - 入門書の皮を被っているが、格子の章でCoppersmith's Attackを扱っており、更に$X$の評価についても載っている
