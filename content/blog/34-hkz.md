+++
title = "HKZ簡約基底の存在性の証明"
date = 2022-09-10

[taxonomies]
tags = ["Lattice"]
+++

※ Typo、記号や添字の誤り、そもそも証明の誤りがありましたら、[Twitter (@Xornet_)](https://twitter.com/Xornet_)へリプライかDM(誰でも送れます)を飛ばすか、[このブログのリポジトリ](https://github.com/Xornet-Euphoria/blog_project_euphoria)でIssueを立てたりプルリクを送ったりしてください。

読者が格子についての知識をある程度有している前提で書いてます。下記のサイトや書籍を読んでいると読みやすいと思います。

<!-- more -->

- [LLLを理解するぞ - みつみつみつですか？](https://mitsu1119.github.io/blog/post/post1/lll/)
- [格子暗号解読のための数学的基礎 | 近代科学社](https://www.kindaikagaku.co.jp/book_list/detail/9784764905986/)
	- 1.1, 1.2, 2.2節は必須、GSOベクトルと格子の関係を上手く理解するために2.3節も読みたい
	- なお、この記事はこの書籍の3.1節の行間を埋めるという目的で書いている

## 格子に関する記法

次のように記号を定義する

- $L$: $n$次元格子
- $\mathrm{vol}(L)$: 格子$L$の体積
- $\\{\boldsymbol b_1, \dots, \boldsymbol b_n\\}$: $L$の基底
	- この記事では行ベクトルで表し、それを縦に並べた行列$B$を$L$の基底行列と呼ぶ
- $\boldsymbol b_i^\* \ (1 \leq i \leq n)$: $\boldsymbol b_i$のGSOベクトル (グラムシュミットの直交化を行ったベクトル)
	- 任意の$1 \leq i \leq n$に対して$\langle\boldsymbol b_1, \dots, \boldsymbol b_i\rangle = \langle \boldsymbol b_1^\*, \dots, \boldsymbol b_i^\*\rangle$が成り立つ
	- ここで$\langle \boldsymbol b_1, \dots, \boldsymbol b_i \rangle := \\{\sum_{j=1}^i r_j\boldsymbol b_j \mid r_j \in \mathbb R\\}$とする
- $\mu_{i,j} \ (1 \leq j \leq i \leq n)$: GSO係数 (便宜上、$\mu_{i,i} = 1$とする)
	- $\boldsymbol b_i = \sum_{j=1}^i \mu_{i,j}\boldsymbol b_j^\*$が成り立つ
- $\pi_i \ (1 \leq i \leq n)$: $\langle \boldsymbol b_1, \dots, \boldsymbol b_{i-1}\rangle$の直交補空間に対する直交射影 ($i=1$の時は便宜上恒等写像とする)
	- つまり$\pi_i\left(\sum_{j=1}^n a_j\boldsymbol b_j^\*\right) = \sum_{j=i}^n a_j\boldsymbol b_j^\*$が成り立ち、特に$\pi_i(\boldsymbol b_i) = \pi_i(\sum_{j=1}^i \mu_{i,j}\boldsymbol b_j^\*) = \boldsymbol b_j^\*$が成り立つ
- $\lambda_i(L) \ (1 \leq i \leq n)$: $i$次逐次最小
	- 本記事では$i=1$の時のみ登場し、$\lambda_1(L)$は$L$の非零な最短ベクトルの長さとなる
	- なお$1 \leq i \leq n$に対して、ノルムが$i$次逐次最小となる格子ベクトルが存在することは知られており、したがって格子における非零な最短ベクトルは存在する(参考文献1: 1.4節)

## 定義: HKZ簡約基底

次を満たす格子$L$の基底$\\{\boldsymbol b_1, \dots, \boldsymbol b_n\\}$を「HKZ簡約基底」と呼ぶ

1. サイズ簡約されている
2. 任意の$1 \leq i \leq n$に対して$\\|\boldsymbol b_i^\*\\| = \lambda_1(\pi_i(L))$を満たす

2の条件に登場する$\pi_i(L)$は$\\{\pi_i(\boldsymbol x) \mid \boldsymbol x \in L\\}$を表す。実はこれは射影格子[^1]と呼ばれる$n-i+1$次元格子になり、$\\{\pi_i(\boldsymbol b_i), \dots, \pi_i(\boldsymbol b_n)\\}$を基底として持つ。

したがって、2の条件は各基底$\boldsymbol b_i$のGSOベクトル$\boldsymbol b_i^\*$のノルムが、射影格子$\pi_i(L)$の第1次逐次最小である、言い換えれば$\boldsymbol b_i^\*$が$\pi_i(L)$の非零な最短ベクトルであるということを要請している。

特に$i=1$に関して、$\boldsymbol b_1^\* = \boldsymbol b_1$であり、更に$\pi_1$は恒等写像であるから、$\\|\boldsymbol b_1\\| = \lambda_1(L)$となって、$\boldsymbol b_1$が$L$の非零な最短ベクトルであることがわかる。

## 構成1: HKZ簡約基底の構成

次のようにして$n$本の$L$の格子ベクトルの組$\\{\boldsymbol b_1, \dots, \boldsymbol b_n\\}$を構成する。

1. $\\|\boldsymbol b_1\\| = \lambda_1(L)$となる格子ベクトル$\boldsymbol b_1$を用意する
2. 射影格子$\pi_2(L)$[^2]の非零な最短ベクトルを$\boldsymbol b_2'$とすると$\boldsymbol b_2' = \pi_2(\boldsymbol b_2)$となる$\boldsymbol b_2 \in L$が存在するはずのでこれを$\boldsymbol b_2$とする
3. 以下同様にして、$i$が小さい方から順に$\pi_i(L)$の非零な最短ベクトル$\boldsymbol b_i'$に対して$\boldsymbol b_i' = \pi_i(\boldsymbol b_i)$となる$\boldsymbol b_i \in L$を選んで基底とする

この手順の3より、$\boldsymbol b_i^\* = \pi_i(\boldsymbol b_i) = \boldsymbol b_i'$となるので、$\boldsymbol b_i'$が$\pi_i(L)$の非零な最短ベクトルであることから、このようにして得られた基底は明らかにHKZ簡約基底の2番目の条件を満たす。

一方で、1番目の条件であるサイズ簡約されている事を満たすとは限らない。しかし、条件2が基底の「GSOベクトル」に依存することからGSOベクトルを変更しない簡約方法であるサイズ簡約(参考文献1: 2.2節, 参考文献2: 6節を参照)を実行しても条件2は崩れない。よって、このようにして得られた基底に対してサイズ簡約を実行すればHKZ簡約基底の2条件は満たされる。

このような構成はどのような格子に対しても行うことが出来るためHKZ簡約基底の2条件を満たす「$n$本の格子ベクトルの組」[^3]は任意の格子に対して存在する。問題は、これが本当に$L$の基底であるかということである。

このように構成したベクトルの集合は$L$のベクトルからなるため$L$の部分格子を生成するが、$L$自体を生成することは自明ではない。よって以下の補題1, 補題2を用いて$L$を生成する事を示す。

## 補題1

任意の$n$次元格子$L$の任意の非零な最短ベクトル$\boldsymbol v$に対して、$L$の基底の中で$v$を含むものが存在する。

$\because)$

格子の次元に関する数学的帰納法で証明する。証明の方針としては、$k$次元格子の基底から1つベクトルを取り除いた基底によって張られる$k-1$次元格子は元の格子の部分格子であり、元の格子の非零な最短ベクトルが含まれているなら、その部分格子でもまた非零な最短ベクトルとなる事を利用する。

$n=1$の場合においては、明らかに補題が成り立つ[^4]。なぜなら、$\boldsymbol x$だけによって張られる1次元格子の非零な最短ベクトルは$\pm \boldsymbol x$の2つであり、$\\{\boldsymbol x\\}$も$\\{-\boldsymbol x\\}$もこの1次元格子の基底になるからである。

$n=k-1 \ (k \geq 2)$において補題が成り立つと仮定して$n=k$の場合を考える。つまり、任意の$k-1$次元格子とその非零な最短ベクトル$\boldsymbol v$に対して、$\boldsymbol v$を基底ベクトルとして含む基底が存在する。

$k$次元格子$L$の非零な最短ベクトルを$\boldsymbol v$とおく。また、$L$の基底として$\\{\boldsymbol b_1, \dots, \boldsymbol b_k\\}$を用意し、基底行列を$B$とおいて$\boldsymbol v = (v_1, \dots, v_k)B$と係数を定義する。

もし$v_i = 0$となるような係数が存在する場合、$\boldsymbol b_i$を$B$から取り除いた基底$C$を考える。元の基底が格子$L$を張っていたことから、$C$は$L$の部分格子を張る基底となる。この$k-1$次元部分格子を$M$とおく。$\boldsymbol v \in M$であり、更に$M$が$L$の部分格子で$\boldsymbol v$が$L$の非零な最短ベクトルであったことから、$\boldsymbol v$は$M$の非零な最短ベクトルでもある。

帰納法の仮定から任意の$k-1$次元格子には任意の非零な最短ベクトルを基底ベクトルとして含むような基底が存在する。よって、$M$の基底の中にはそのようなもの、つまり$\boldsymbol v$を含むものが存在することから、これを$C'$とおくと、$C'$と$C$は当然同じ格子を張る。

したがって、$C'$に上記で除去した$\boldsymbol b_i$を加えた基底を$C$とおけば[^5]、$C$は$B$と同じ格子を生成する。$C$の構成方法から、$C$は明らかに$\boldsymbol v$、つまり$L$の非零な最短ベクトルを基底に含むことから、この場合は補題が成り立ち、数学的帰納法を用いて任意の次元において補題が成り立つ。

<!-- また、$i < j \land v_i = v_j$となる係数が存在する場合は$i$番目の基底ベクトルを$\boldsymbol b_i + \boldsymbol b_j$として格子の基底を変更する。これで基底は$\\{\boldsymbol b_1, \dots, \boldsymbol b_i + \boldsymbol b_j, \dots, \boldsymbol b_j, \dots \boldsymbol b_k\\}$となって、$\boldsymbol v$に対する新しい係数$v'_l$は$v'_l = \begin{cases}0 & l = j \cr v_l & l \neq j\end{cases}$となる。

これで$\boldsymbol v$の係数に0が含まれる$L$の基底が得られたことから、先程と同様にして示すことが出来る。

-->

$\boldsymbol v$(の係数)がこれを満たさない場合を考える。

$g := \gcd(v_1, v_2), w_1 = v_1/g, w_2 = v_2/g$と定義すると、$aw_1 + bw_2 = 1$となるような整数$a,b$が存在する。これを用いると次の行列$U$はユニモジュラ行列[^6]になる。

$$
U = \begin{pmatrix}
w_1 & w_2 &  & \cr
-b & a &  &  \cr
&&1 &  \cr
&&&1 & \cr
&&&& \ddots \cr
&&&&& 1
\end{pmatrix}
$$

よって、$B$と$UB$は共に格子$L$を生成し、$UB$は次のような基底行列となる。

$$
UB = \begin{pmatrix}
w_1\boldsymbol b_1 + w_2\boldsymbol b_2 \cr
\boldsymbol b_2' \cr
\boldsymbol b_3 \cr
\vdots \cr
\boldsymbol b_k
\end{pmatrix}
$$

ここで、$\boldsymbol b_2' := -b\boldsymbol b_1 + a\boldsymbol b_2$とおいた。

この$L$の基底$UB$に対する$\boldsymbol v$の係数は、$w_1, w_2$の定義から$(g, 0, v_3, \dots, v_k)$となる(つまり$\boldsymbol v = (g, 0, v_3, \dots, v_k)UB$が成り立つ)。よって、係数に0が含まれるような$L$の基底を用意出来たことから、この場合もまた、最初の場合と同様にして補題が成り立つ事を示す事が出来る。 $\Box$

---

補題2の提示と証明の前に、次のように射影格子に関する記号を定義する。

$1 \leq k \leq n$に対して、射影格子$L^{(k)} := \pi_k(L)$を考えると、この格子は$n-k+1$次元格子であり、基底として$\\{\pi_k(\boldsymbol b_k), \dots, \pi_k(\boldsymbol b_n)\\}$が存在する。以後、わかりやすさのためにこの基底を$\\{\boldsymbol b_1^{(k)}, \dots, \boldsymbol b_{n-k+1}^{(k)}\\}$とおく。つまり次が成り立つ。

$$
\boldsymbol b_i^{(k)} := \pi_k(\boldsymbol b_{k+i-1})
$$

これに限らず、$(k)$を上付き添字で用いる時は$L^{(k)}$に関する数学的対象を表す。

特に、$1\leq i \leq n-k+1$に対して、$\langle \boldsymbol b_1^{(k)}, \dots, \boldsymbol b_{i-1}^{(k)}\rangle$の直交補空間への直交射影を$\pi_i^{(k)}$で表す。通常の場合と同様に、$i=1$の時は恒等写像とする。

また、以降のために必要な命題として参考文献1の1.2節より定理1.2.5を引用する。

(定理1.2.5) $n$次元格子$L$の基底$\\{\boldsymbol b_1, \dots, \boldsymbol b_n\\}$と整数$2\leq l \leq n$に対して次が成り立つ。

$$
\mathrm{vol}(\pi_l(L)) =\frac{\mathrm{vol}(L)}{\mathrm{vol}(\mathcal L(\boldsymbol b_1, \dots, b_{l-1}))}
$$

特に$l=2$の場合を系として以後用いる

## 系1

$n$次元格子$L$の基底$\\{\boldsymbol b_1, \dots, \boldsymbol b_n\\}$に対して次が成り立つ。

$$
\mathrm{vol}(\pi_2(L)) =\frac{\mathrm{vol}(L)}{\mathrm{vol}(\mathcal L(\boldsymbol b_1))} =\frac{\mathrm{vol}(L)}{\\|\boldsymbol b_1\\|}
$$

---

## 補題2

構成1によって作られた格子ベクトルの組$\\{\boldsymbol b_1, \dots, \boldsymbol b_n\\}$が生成する格子を$M$とする。この時、$\mathrm{vol}(M) = \mathrm{vol}(L)$が成り立つ。

$\because)$

(※ $n$に関する数学的帰納法で多分示すことが出来ますが、面倒なのでやってないです)

補題1より、$L$の基底$C := \\{\boldsymbol c_1, \dots, \boldsymbol c_n\\}$の中で、$\boldsymbol c_1 = \boldsymbol b_1$となるものが存在する。系1を$L$の基底を$C$として、$l=2$で適用する[^7]と次が成り立つ。なお、当然のことだが直交射影$\pi_2$は基底$C$に依存している。

$$
\mathrm{vol}(\pi_2(L)) = \frac{\mathrm{vol}(L)}{\mathrm{vol}(\mathcal L(\boldsymbol c_1))} = \frac{\mathrm{vol}(L)}{\\|\boldsymbol c_1\\|} = \frac{\mathrm{vol}(L)}{\\|\boldsymbol b_1\\|} = \frac{\mathrm{vol}(L)}{\\|\boldsymbol b_1^\*\\|}
$$

射影格子$L^{(2)}$についても同様の事を考える。この格子は先程定義した$\boldsymbol c_1$に依存するが、$\boldsymbol c_1 = \boldsymbol b_1$であるから、$\boldsymbol b_2^\*$は$L^{(2)}$の非零な最短ベクトルとなり、更にこれを基底ベクトルとして含むものが存在することが補題1から言える。つまりこの基底を$C^{(2)} := \\{\boldsymbol c^{(2)}_1, \dots, \boldsymbol c^{(2)}\_{n-1}\\}$とおくと、$\boldsymbol c^{(2)}_1 = \boldsymbol b_2^\*$が成り立つ。よって系1を$L^{(2)}$の基底を$C^{(2)}$として適用すると次が成り立つ。

$$
\mathrm{vol}(\pi^{(2)}_2(L^{(2)})) = \frac{\mathrm{vol}(L^{(2)})}{\mathrm{vol}(\mathcal L(\boldsymbol c^{(2)}_1))} = \frac{\mathrm{vol}(L^{(2)})}{\\|\boldsymbol c^{(2)}_1\\|} = \frac{\mathrm{vol}(L^{(2)})}{\\|\boldsymbol b_2^\*\\|}
$$

また、$L^{(2)}$が$\\{c_1^{(2)}, \dots, c_{n-1}^{(2)}\\} = \\{\boldsymbol b_2^\*, \dots, c_{n-1}^{(2)}\\}$で生成されることから、$\pi^{(2)}_2(L^{(2)})$は$\langle \boldsymbol b_1 \rangle$の直交補空間への直交射影の$L$の像を$\langle \boldsymbol b_2^\* \rangle$の直交補空間への直交射影に入れた像になる。したがって、結局$\langle \boldsymbol b_1, \boldsymbol b_2^\* \rangle = \langle \boldsymbol b_1, \boldsymbol b_2 \rangle$の直交補空間への直交射影をとっているため、これに対する格子$L$の像が$L^{(3)}$になり前述の式は次のように書き直すことが出来る。

$$
\mathrm{vol}(L^{(3)}) = \frac{\mathrm{vol}(L^{(2)})}{\\|\boldsymbol b_2^\*\\|}
$$

これと同様の事を添え字を増やしながら行っていくと、$L^{(k)}$は$\langle \boldsymbol b_1^\*, \dots, \boldsymbol b_{k-1}^\*\rangle$の直交補空間への直交射影の$L$の像となり、更に構成1と補題1、系1から、任意の$2 \leq k \leq n$に対して次が成り立つ。

$$
\mathrm{vol}(L^{(k)}) = \frac{\mathrm{vol}(L^{(k-1)})}{\\|\boldsymbol b_{k-1}^\*\\|}
$$

よって、$k=n$に対して次が成り立つ。

$$
\mathrm{vol}(L^{(n)}) = \frac{\mathrm{vol}(L^{(n-1)})}{\\|\boldsymbol b_{n-1}^\*\\|} = \frac{\mathrm{vol}(L^{(n-2)})}{\\|\boldsymbol b_{n-1}^\*\\|\\|\boldsymbol b_{n-2}^\*\\|} = \cdots = \frac{\mathrm{vol}(L^{(1)})}{\prod_{i=1}^{n-1}\\|\boldsymbol b_i^\*\\|}
$$

ここで、$\mathrm{vol}(L^{(n)})$は$\langle \boldsymbol b_1^\*, \dots, \boldsymbol b_{n-1}^\*\rangle$の直交補空間への直交射影の$L$の像となることから、構成1より$\mathrm{vol}(L^{(n)}) = \mathrm{vol}(\langle \boldsymbol b_n^\* \rangle) = \\|\boldsymbol b_n^\*\\|$が成り立つ。また、$L^{(1)} = L$であるから上式に代入、移項して次が成り立つ。

$$
\prod_{i=1}^n \\|\boldsymbol b_i^\*\\|= \mathrm{vol}(L)
$$

左辺は$\mathrm{vol}(M)$に等しいことから、$\mathrm{vol}(M) = \mathrm{vol}(L)$が成り立つ。 $\Box$

## 定理: HKZ簡約基底の存在

任意の格子$L$に対して構成1で構成した基底は$L$のHKZ簡約基底である。

$\because)$

構成1で述べたように、HKZ簡約基底の2条件は満たしているので後は「$L$の基底」、つまり$L$を生成する事を言えば良い。

$L$の任意の部分格子$M$に対して、$\rho := \frac{\mathrm{vol}(M)}{\mathrm{vol}(L)}$とおくと、次が成り立つことが知られている(参考文献1: 1.1節)。

$$
\rho L \subset M \subset L
$$

よって$\rho = 1$であれば、$L=M$となる。

構成1によって作られた基底$\\{\boldsymbol b_1, \dots, \boldsymbol b_n\\}$によって生成される格子$M$は$L$の部分格子である。また、補題2より$\mathrm{vol}(M) = \mathrm{vol}(L)$が成り立つ。

以上より、$\rho = \frac{\mathrm{vol}(M)}{\mathrm{vol}(L)} = 1$であることから$L=M$が成り立つため、この基底は$L$を生成する。 $\Box$

## 参考文献

1. [格子暗号解読のための数学的基礎 | 近代科学社](https://www.kindaikagaku.co.jp/book_list/detail/9784764905986/)
2. [LLLを理解するぞ - みつみつみつですか？](https://mitsu1119.github.io/blog/post/post1/lll/)

---

[^1]: 射影格子に関しては参考文献1の1.2節が非常に詳しく、性質や定理もここから引用している

[^2]: この射影格子は既に$\boldsymbol b_1$を選んでいるので定義出来る。以降も同様の事をするが既に小さい添字についての基底ベクトルを選んでいるので射影格子が定義出来る

[^3]: これまで、そしてこれからも単に$n$本の格子ベクトルの集合を「基底」と呼ぶことがあるが、格子$L$を生成することを示していない(これから示す)ため、「$L$の基底」とすることは厳密には誤りである。よってそれを強調するために、このような表現を用いた

[^4]: $n\leq 4$までの$n$においては逐次最小基底が存在することから補題が成立することが言える。詳しくは参考文献1: 1.4, 1.5節を参照のこと

[^5]: $C$が一次独立であることは明らか

[^6]: 行列式の絶対値が1であるような行列のこと。ある基底行列にユニモジュラ行列を左(基底が列ベクトルなら右)からかけて出来る基底行列も同じ格子を張るという性質がある(参考文献1: 1.1節, 参考文献2: 1, 2節)

[^7]: 当然だが、射影格子も名前の通り「格子」であるので系1を用いることが出来る