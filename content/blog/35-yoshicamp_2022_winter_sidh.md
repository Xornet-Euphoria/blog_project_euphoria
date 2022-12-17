+++
title = "yoshi-camp 2022 winter 参加記 (SIDH編)"
date = 2022-12-17

[taxonomies]
tags = ["CTF", "Crypto", "SIDH", "Elliptic_Curve"]
+++

## 序文

毎年zer0ptsの皆さんが行っている高レベルな集団講義であるyoshi-campですが、例年なら指を咥えながら外側から眺めて終了後の残滓を必死で解読[^1]していたのが、今年はTwitterで外部参加者を募集していたので、./Vespiaryから私とﾈｺﾁｬﾝが参加したいと伝えたところ、誠にありがたいことに快諾していただいたので参加してきました。というわけで恒例の参加記を書きます。

<!-- more -->

……と、言いたかったんですが、講義は(私の発表分も含めて)5つもあり、どれも高レベルかつ演習量が多かった事から、どの講義も用意された分を全部こなすことは無く終わってしまったので復習が完了した講義から参加記を書きます。そういうわけでこの記事は最初に行われた[ふるつき](https://twitter.com/theoremoon)さんによる「猫と学ぶ同種写像暗号」の記録と復習になります。

## 他の人の参加記

- [yoshi-camp 2022 winter参加記【Day 0-1】 - CTFするぞ](https://ptr-yudai.hatenablog.com/entry/2022/12/13/235034): 先行レポート。隠す必要も無いので言うが、今回の復習はこの記事を大いに参考にした

(※ ここまで敬体で書いていますが、自分がWriteupや技術や数学に関する記事を書く時の癖で、次の節から常体で書きます)

## 同種写像

楕円曲線$E$から、別の楕円曲線$E'$への写像$\phi: E \to E'$で、次を満たすものを同種写像と呼ぶ。

1. 有理関数で表す事が出来る
2. 全射
3. $\phi(O_E) = O_{E'}$

(理由はよくわかっていないし、今後もそんな感じで根拠不明の説明になってしまうが、)これは準同型写像になり、この性質は後にSIDHで活躍する。

同種写像に関する重要な命題として次のようなものがある。

楕円曲線$E(\mathbb F_p)$と$H \in E(\overline {\mathbb F_p})$が与えられた時に、$\ker \phi = \langle H \rangle$となる同種写像$\phi: E \to E'$と、終域となる楕円曲線$E'$が(同型を除いて)一意的に存在する。この時$E' = E/\langle H \rangle$のように書く。また、以降では楕円曲線が「同じ」と言った時に大抵は「同型」を意味するものとする。

特に$H$を$E(\overline {\mathbb F_p})$の$l$-ねじれ点($l$倍すると無限遠点になる点)とすれば、$\phi$は$l$次の同種写像($l$-同種写像と呼ばれる)となり、$\psi \circ \phi = [l]$となるような同種写像$\psi: E' \to E$も存在して「双対同種写像」と呼ばれる。

そういうものの存在がわかったところで、実用するためには計算が出来ないとあまり意味がないが、これはちゃんと計算できてSageMathには実装が存在する。楕円曲線`E`と、生成元`H`に対して`E.isogeny(H)`を叩けば対応する同種写像が求められる。

というわけで、このメソッドを用いて以上の事を確かめてみる。講義では、与えられた楕円曲線に対して2-isogenyと3-isogenyを計算し、双対な同種写像が存在する事を確かめるという問題が出た。

```python
p = 2^143 * 3 - 1
K = GF(p^2)
E = EllipticCurve(K, [1, 0])  # y^2 = x^3 + x
j_E = E.j_invariant()

# exercise1
l = 3
for x, _ in E.division_polynomial(l).roots():
    P = E.lift_x(x)
    phi = E.isogeny(P)
    _E = phi.codomain()

    found = False
    for _x, _ in _E.division_polynomial(l).roots():
        Q = _E.lift_x(_x)
        psi = _E.isogeny(Q)
        __E = psi.codomain()

        # __E != E but they have same j-invariant
        if j_E == __E.j_invariant():
            assert __E.is_isomorphic(E)
            found = True

            # psi \circ phi = [l] (duality)
            # ref: https://doc.sagemath.org/html/en/reference/arithmetic_curves/sage/schemes/elliptic_curves/ell_generic.html?highlight=isomorphism_to#sage.schemes.elliptic_curves.ell_generic.EllipticCurve_generic.isomorphism_to
            f = __E.isomorphism_to(E)
            R = E.random_point()
            print(-1 * f(psi(phi(R))) == l*R)  # `-1` is needed ([-1] \circ f is also an isomorphism from `__E` to `E`)
            break

    assert found
```

$l$-ねじれ点のx座標は$E$の$l$等分多項式の根となっているので、(無限遠点を除いて)`E.division_polynomial(l)`で求める事が出来る。なお、`E(0).divison_points(l)`を用いると$l$-ねじれ点を全て求める事が出来るが、($l \neq 2$である)$l$-ねじれ点$P$に対して、$-P$はx座標が同じでy座標が異なる$l$-ねじれ点となり、これもこのメソッドで手に入る。そして不思議な事情で、`E.isogeny(P)`と`E.isogeny(-P)`は同じになるようなので、過不足なく求めたいのなら等分多項式を用いる方が良い。

講義中では、2-isogenyと3-isogenyを求めるだけで満足してしまったので、同種写像$\phi$に対応する双対同種写像も求めてみる。これも終域$E'$に対して、等分多項式から$l$-ねじれ点を求めてそれを生成元とする部分群がkernelとなる同種写像$\psi$を`.isogeny()`で求める事が出来るので、その終域が$E$と同型、つまりj不変量が同じものが見つかれば良い。

あとは$E$と同型な$E_0$から$E$への同型写像$f$が`.isomorphism_to(E)`で手に入るので、$f\circ \psi \circ \phi = [l]$を確かめれば良い。但し、これまた不思議な力が働いて$l$倍写像$[l]$ではなく、$-l$倍写像になってしまうが、細かいことはとりあえず気にしないでおく($f$が同型写像なら、$[-1] \circ f$も同型写像になるのであまり問題は無い)

ちなみに、これは演習後に教えてもらったのだが、単に$l$-同種写像が欲しくて$l$が素数なら、こんな難しい事をしなくても`E.isogenies_prime_degree(l)`で手に入るらしい。

## $l^e$-同種写像の計算

一般的に$l$-同種写像を求める計算は$l$がデカければデカいほど重くなるらしく、$l^e$のようなものは$e$が少し増えただけでもかなり計算時間がかかってしまう。そこで、$l$-同種写像で$e$回移して合成する事を考えると、またしても不思議な力が働いて[^2]$l^e$-同種写像を計算出来るらしい。

2つ目の課題としてこれの実装が課された。$l^e$-同種写像「自体」を求めようとすると関数合成によって次数が爆発してしまうので引数に計算した点(後でSIDHを実装する都合上、複数とれるようにしている)を渡すと$l$-同種写像を計算する度に移すという形にしている。

```python
p = 2^143 * 3 - 1
K = GF(p^2)
E = EllipticCurve(K, [1, 0])  # y^2 = x^3 + x
j_E = E.j_invariant()


def prime_power_isogeny(H, l, e, check=False, Ps=[]):
    # check H is a l^e-torsion point of E
    if check:
        assert l^e * H == E(0)

    curve = H.curve()
    for i in range(e):
        # get l-torsion point from H (l^(e-i)-torsion point)
        _H = l^(e - i - 1) * H
        phi = curve.isogeny(_H)
        # update
        curve = phi.codomain()
        H = phi(H)

        Ps = [phi(P) for P in Ps]

    return curve, Ps

# exercise2
l = 2
e = 10

# get l^e-torsion point
while True:
    P = E.random_point()
    o = P.order()
    if o % l^e == 0:
        P *= (o // l^e)
        break

_E, _ = prime_power_isogeny(P, l, e, True)
print(_E.j_invariant())
```

ちなみに、これまた演習後に教えてもらったのだが、SageMathのバージョンが9.5以上だと`E.isogeny(H, algorithm="factored")`とすることで同様の事が出来るらしい。残念ながら私が使っているSageMathは演習中は9.0で、自室で使っているデスクトップも9.3だったので未対応である。

## CGLハッシュ

ここまで説明していなかったが、$l$-同種写像はどうやら$l+1$個あるらしい。$l$-同種写像$\phi: E \to E'$に関して、$E'$を定義域とする$l$-同種写像$\psi: E' \to E_i$もまた$l+1$個存在するが、その内1つは双対性より$E$(と同型な楕円曲線)が終域となる。よって、元の定義域$E$に戻らない同種写像は$l$個存在することになる。

ここで、もし$l=2$とすれば、定義域に戻らない同種写像が2つ存在することになるので、ある数値を入力にとってそのビットを下から見ていき、0,1でどちらの同種写像を使うかを決定するという事を考える。これを利用してハッシュ関数が構成出来る、という<s>トチ狂った</s>考えで提唱されたのがCGLハッシュである。

これの実装が3番目の課題として課されたが、講義中は実装が重すぎるという事で見送られた。復習で扱うにも面倒でCTF的にもあまり面白いものではない(出題例が特に無いし、実装例も見当たらないらしい)ので私は説明だけに留める(冒頭でリンクを貼っているptr-yudaiさんの参加記には載っている)。

## SIDH

「ある同種写像$\phi$が存在して、2つの楕円曲線$E, E' := \phi(E)$が与えられた時、$\phi$を求める」という問題が困難だという仮定[^3]を置いて鍵共有が構成出来る。

大まかな流れとしては、$\phi_A: E \to E_A, \phi_B: E\to E_B$となる2つの同種写像を秘密鍵として、$\phi_A': E_B \to E_{BA}$と$\phi_B': E_A \to E_{AB}$という同種写像を計算し、同型の楕円曲線$E_{AB}, E_{BA}$を共有するという様になっている(同型な楕円曲線を共有するので、同一の「値」としては楕円曲線のj不変量を共有することになる)。

使うパラメータは素数$p = l_A^{e_A}l_B^{e_B} - 1$とSupersingularな楕円曲線$E(\mathbb F_p^2)$、$P_A, Q_A \in E[l_A^{e_A}], P_B,Q_B \in E[l_B^{e_B}]$であり、$E[x]$は$x$-ねじれ点全体からなる集合[^4]を意味する。また、$P_A, Q_A$は線形独立(つまり$sP_A + tQ_A = O$となる$s,t$は0以外に存在しない)で、$P_B, Q_B$も線形独立とする。

Aliceは秘密鍵$s_A$を$l_A^{e_A} - 1$以下の非負整数から選択する。同様にBobは秘密鍵$s_B$を$l_B^{e_B} - 1$以下の非負整数から選択する。

2つ目の秘密鍵としてAliceは$\phi_A = E/\langle P_A + s_A Q_A \rangle$を、Bobは$\phi_B = E/\langle P_B + s_B Q_B \rangle$を計算する。

公開鍵としてAliceは$\phi_A(P_B), \phi_A(Q_B)$を計算し、$\phi_A$の終域$E_A := \phi_A(E)$と併せて公開する。同様にBobは$\phi_B(P_A), \phi_B(Q_A), E_B := \phi_B(E)$を公開する。

この後、AliceとBobはそれぞれ、$\phi_A', \phi_B'$を相手の公開鍵と自分の秘密鍵を用いて計算する。これは次のようにして計算出来る。

$$
\begin{aligned}
\phi_A' &= E_B / \langle \phi_B(P_A) + s_A \phi_B(Q_A) \rangle \cr
\phi_B' &= E_A / \langle \phi_A(P_B) + s_B \phi_A(Q_B) \rangle
\end{aligned}
$$

ここで、同種写像の準同型性から$\ker \phi_A' = \langle \phi_B(P_A + s_AQ_A) \rangle = \phi_B(\ker \phi_A)$となり、同様に$\ker \phi_B' = \langle \phi_A(P_B + s_B Q_B) \rangle = \phi_A(\ker \phi_B)$が成り立つ。最終的に$\phi_A' \circ \phi_B$と$\phi_B' \circ \phi_A$がどちらも同じkernelを持つことを示すために、それぞれのkernelに関して考察する。

まず前者に関して、$X \in \ker (\phi_A' \circ \phi_B)$となる任意の$X$に対して、$\ker \phi_A' = \phi_B(\phi_A)$であるから、ある$Y \in \ker \phi_A$が存在して、$\phi_B(X) = \phi_B(Y)$を満たさなくてはならない。よって、$\phi_B(X - Y) = O$となるから、$X - Y \in \ker \phi_B = \langle P_B + s_BQ_B \rangle$が成り立つ。更に$Y \in \ker \phi_A = \langle P_A + s_AQ_A \rangle$であるから、係数$v, w$を用いて$X$は次のように表す事が出来る

$$
X = v(P_A + s_AQ_A) + w(P_B + s_BQ_B)
$$

よって、$X \in \langle P_A + s_A Q_A, P_B + s_B Q_B \rangle$が成り立つことから、$\ker (\phi_A' \circ \phi_B) \subset \langle P_A + s_A Q_A, P_B + s_B Q_B \rangle$が成り立つ。

逆向きも示す事が出来て、$\langle P_A + s_A Q_A, P_B + s_B Q_B \rangle$の$P_B + s_BQ_B$成分は$\ker \phi_B = \langle P_B + s_BQ_B \rangle$より無限遠点となり、$P_A + s_AQ_A$成分は$\phi_B$によって$\phi_B(\ker \phi_A)$の成分となるから、$\ker \phi_A'$となって無限遠点となる。

以上より、$\ker (\phi_A' \circ \phi_B) = \langle P_A + s_A Q_A, P_B + s_B Q_B \rangle$が成り立ち、これを添字を変える事で$\ker (\phi_B' \circ \phi_A) = \langle P_a + s_AQ_A, P_B + s_BQ_B \rangle$を示す事が出来る。

これで、同一の核を持つことから、同種写像としても同じ(特に終域の楕円曲線のj不変量)ものとなるので、AliceとBobで同じ値を共有出来ることとなる。

4番目の課題としてSIDHの実装をテンプレートが配られた上で課されたので次のように実装した。

```python
import sys
import json

# public parameters
(lA, eA), (lB, eB) = (2, 91), (3, 57)
(lA, eA), (lB, eB) = (2, 250), (3, 159)
p = lA**eA * lB**eB - 1
assert is_prime(p)

F = GF(p**2, "z")
E = EllipticCurve(F, [1, 0])
PA, QA = lB**eB * E.gen(0), lB**eB * E.gen(1)  # PA, QA \in E[lA**eA]
PB, QB = lA**eA * E.gen(0), lA**eA * E.gen(1)  # PB, QB \in E[lB**eB]

assert (lA**eA * PA).is_zero()
assert (lA**eA * QA).is_zero()
assert (lB**eB * PB).is_zero()
assert (lB**eB * QB).is_zero()


def encode_p2(v):
    """encode v in F_{p^2} into json serializable"""
    v = v.polynomial()
    return [int(x) for x in list(v)]


def decode_p2(xs):
    return F(xs)


def prime_power_isogeny(H, l, e, check=False, Ps=[]):
    # check H is a l^e-torsion point of E
    if check:
        assert l^e * H == E(0)

    curve = H.curve()
    for i in range(e):
        # get l-torsion point from H (l^(e-i)-torsion point)
        _H = l^(e - i - 1) * H
        phi = curve.isogeny(_H)
        # update
        curve = phi.codomain()
        H = phi(H)

        Ps = [phi(P) for P in Ps]

    return curve, Ps


if __name__ == '__main__':
    # generate pub/priv parameters
    if sys.argv[1] == "alice":
        # ...
        sA = randint(0, lA**eA - 1)
        EA, UV = prime_power_isogeny(PA + sA*QA, lA, eA, Ps=[PB, QB])
        U = UV[0]
        V = UV[1]
        UAx, UAy = U.xy()
        VAx, VAy = V.xy()
        aA,bA = EA.a4(), EA.a6()

        # exchange parameters
        # {
        #   E: {a: ..., b: ...}  # parameter of curve. E: y^2 = x^3 + ax + b
        #   U: {x: ..., y: ...}  # coordinates of phi(P)
        #   V: {x: ..., y: ...}  # coordinates of phi(Q)
        # }
        print(json.dumps({
            "U": {"x": encode_p2(UAx), "y": encode_p2(UAy)},
            "V": {"x": encode_p2(VAx), "y": encode_p2(VAy)},
            "E": {"a": encode_p2(aA), "b": encode_p2(bA)},
        }))
        params = json.loads(input())

        # ...
        EBa = decode_p2(params["E"]["a"])
        EBb = decode_p2(params["E"]["b"])
        EB = EllipticCurve(F, [EBa, EBb])
        UB = params["U"]
        UBx = decode_p2(UB["x"])
        UBy = decode_p2(UB["y"])
        UB = EB((UBx, UBy))
        VB = params["V"]
        VBx = decode_p2(VB["x"])
        VBy = decode_p2(VB["y"])
        VB = EB((VBx, VBy))

        EBA, _ = prime_power_isogeny(UB + sA*VB, lA, eA)

        shared = EBA.j_invariant()

        print("shared key is:", shared, file=sys.stderr)

    elif sys.argv[1] == "bob":
        # ...
        sB = randint(0, lB**eB - 1)
        EB, UV = prime_power_isogeny(PB + sB*QB, lB, eB, Ps=[PA, QA])
        U = UV[0]
        V = UV[1]
        UBx, UBy = U.xy()
        VBx, VBy = V.xy()
        aB,bB = EB.a4(), EB.a6()

        # exchange parameters
        # {
        #   E: {a: ..., b: ...}  # parameter of curve. E: y^2 = x^3 + ax + b
        #   U: {x: ..., y: ...}  # coordinates of phi(P)
        #   V: {x: ..., y: ...}  # coordinates of phi(Q)
        # }
        print(json.dumps({
            "U": {"x": encode_p2(UBx), "y": encode_p2(UBy)},
            "V": {"x": encode_p2(VBx), "y": encode_p2(VBy)},
            "E": {"a": encode_p2(aB), "b": encode_p2(bB)},
        }))

        params = json.loads(input())
        # ...
        EAa = decode_p2(params["E"]["a"])
        EAb = decode_p2(params["E"]["b"])
        EA = EllipticCurve(F, [EAa, EAb])
        UA = params["U"]
        UAx = decode_p2(UA["x"])
        UAy = decode_p2(UA["y"])
        UA = EA((UAx, UAy))
        VA = params["V"]
        VAx = decode_p2(VA["x"])
        VAy = decode_p2(VA["y"])
        VA = EA((VAx, VAy))

        EAB, _ = prime_power_isogeny(UA + sB*VA, lB, eB)

        shared = EAB.j_invariant()

        print("shared key is:", shared, file=sys.stderr)
```

ちなみに、演習中は何故か動かなかったのだが、`prime_power_isogeny()`の`l, e`引数をAliceとBobで逆にしていたのが原因だったので帰ってきてここを直したら動いた。

## GPST Attack

SIDHに対する攻撃として有名なものに、この夏に発表されたそもそもSIDH自体が脆弱だというものがあるが、それ以外にも攻撃が存在し、特にAliceが同一の秘密鍵$s_A$を使いまわしている時に、Bobが自由な値でSIDHを実行出来てしかも鍵共有の可否(同一の値が両者で共有されたか?)が判明する時にAliceの秘密鍵$s_A$をリーク出来る攻撃がGPST Attackである。

末尾1bitをリークする例が簡単なのでまずそれから紹介する。Bobは公開鍵として$\phi_B(P_A), \phi_B(Q_A), E_B$をAliceに渡すが、$\phi_B(Q_A)$の代わりに$l_A^{e_A - 1} \phi_B(P_A) + \phi_B(Q_A)$を送る事を考える。

この時Aliceがプロトコル通りにSIDHを実行すると次を計算して同種写像$\phi_A'$を計算する。

$$
\begin{aligned}
\phi_A' &= E_B/ \langle \phi_B(P_A) + s_A(l_A^{e_A - 1} \phi_B(P_A) + \phi_B(Q_A)) \cr
&= E_B/ \langle (\phi_B(P_A) + s_A\phi_B(Q_A)) + s_Al_A^{e_A - 1} \phi_B(P_A) \rangle
\end{aligned}
$$

ここで、$P_A$は$l_A^{e_A - 1}$-ねじれ点なのでもし$s_A$が$l_A$を約数として含んでいれば、$s_Al_A^{e_A - 1}\phi_B(P_A) = O$になる。特にSIDHでは$l_A = 2$が用いられる事が多いので$s_A$が偶数なら、$O$になるし、奇数なら非零な点となる。

これによって$\phi_A'$の形も変わり、$s_A$が偶数の時は余分な項が無限遠点となるので、Bobが$\phi_B(Q_A)$を通常通り公開した時と何ら変わらない同種写像となり、何の問題もなく鍵共有が行われる。一方、$s_A$が奇数の時は、$s_A l_A^{e_A - 1} \phi_B(P_A)$が無限遠点とならないため、核が異なることから通常とは別の同種写像となり、Bobとは別の楕円曲線が終域となる。よって、AliceとBobとで異なるj不変量が計算されることから、鍵共有は失敗する。

したがって、この成否をオラクルとして得られるのであれば、$s_A$の末尾ビットをリーク出来る。

1bitだけリーク出来てもあまり嬉しさは無いが、これを応用することで$s_A$の全てをリーク出来る。このためには$\phi_B(P_A), \phi_B(Q_A)$を次のように変える。

$$
\begin{aligned}
\phi_B(P_A) &\to \phi_B(P_A) - 2^{e_A-i-1}K_i\phi_B(Q_A) \cr
\phi_B(Q_A) &\to (1+2^{e_A-i-1})\phi_B(Q_A)
\end{aligned}
$$

ここで$i$は特定したいビットのインデックスで、$K_i$は$i$未満の既知ビット(但し$K_0 = 0$)とする。この状況でAliceは次のような同種写像を計算する。

$$
\begin{aligned}
\phi_A' &= E_B/\langle \phi_B(P_A) - 2^{e_A-i-1}K_i\phi_B(Q_A) + s_A(1+2^{e_A-i-1})\phi_B(Q_A) \rangle \cr
&= E_B/ \langle (\phi_B(P_A) + s_A\phi_B(Q_A)) + 2^{e_A - i - 1}(s_A - K_i)\phi_B(Q_A) \rangle
\end{aligned}
$$

ここで、$s_A - K_i$は末尾$i$ビットが0となるので$2^i$の倍数となる。よって、もし$s_A$の$i$ビット目が0であれば$2^{i+1}$の倍数となり、1であれば$2^{i+1}$の倍数とはならない。その前の係数$2^{e_A - i - 1}$と併せて考えると、$s_A$の$i$ビット目が0なら$2^{eA}\phi_B(Q_A) = O$となり、一方で1なら無限遠点には収まらない。というわけで先ほどと同様のオラクルがあれば$s_A$が使い回されている限りは全てのビットをリーク出来る。

講義では、前節のSIDHのAlice[^5]に対して攻撃を行う課題が宿題として課されたので次のようなスクリプトで解いた。

```python
import sys
import json
from pwn import remote

# public parameters
(lA, eA), (lB, eB) = (2, 250), (3, 159)
p = lA**eA * lB**eB - 1
assert is_prime(p)

F = GF(p**2, "z")
E = EllipticCurve(F, [1, 0])
PA, QA = lB**eB * E.gen(0), lB**eB * E.gen(1)  # PA, QA \in E[lA**eA]
PB, QB = lA**eA * E.gen(0), lA**eA * E.gen(1)  # PB, QB \in E[lB**eB]

assert (lA**eA * PA).is_zero()
assert (lA**eA * QA).is_zero()
assert (lB**eB * PB).is_zero()
assert (lB**eB * QB).is_zero()


def encode_p2(v):
    """encode v in F_{p^2} into json serializable"""
    v = v.polynomial()
    return [int(x) for x in list(v)]


def decode_p2(xs):
    return F(xs)


def prime_power_isogeny(H, l, e, check=False, Ps=[]):
    # check H is a l^e-torsion point of E
    if check:
        assert l^e * H == E(0)

    curve = H.curve()
    for i in range(e):
        # get l-torsion point from H (l^(e-i)-torsion point)
        _H = l^(e - i - 1) * H
        phi = curve.isogeny(_H)
        # update
        curve = phi.codomain()
        H = phi(H)

        Ps = [phi(P) for P in Ps]

    return curve, Ps


known = 0
i = 0
while i < 200:
    sc = remote("localhost", 13337)
    # ...
    sB = randint(0, lB**eB - 1)
    EB, UV = prime_power_isogeny(PB + sB*QB, lB, eB, Ps=[PA, QA])
    U = UV[0]
    V = UV[1]
    _U = U - lA^(eA - i - 1)*known*V
    _V = (1 + lA^(eA - i - 1)) * V
    UBx, UBy = _U.xy()
    VBx, VBy = _V.xy()
    aB,bB = EB.a4(), EB.a6()

    # exchange parameters
    # {
    #   E: {a: ..., b: ...}  # parameter of curve. E: y^2 = x^3 + ax + b
    #   U: {x: ..., y: ...}  # coordinates of phi(P)
    #   V: {x: ..., y: ...}  # coordinates of phi(Q)
    # }
    payload = json.dumps({
        "U": {"x": encode_p2(UBx), "y": encode_p2(UBy)},
        "V": {"x": encode_p2(VBx), "y": encode_p2(VBy)},
        "E": {"a": encode_p2(aB), "b": encode_p2(bB)},
    })

    params = json.loads(sc.recvline())
    sc.sendline(payload.encode())
    # ...
    EAa = decode_p2(params["E"]["a"])
    EAb = decode_p2(params["E"]["b"])
    EA = EllipticCurve(F, [EAa, EAb])
    UA = params["U"]
    UAx = decode_p2(UA["x"])
    UAy = decode_p2(UA["y"])
    UA = EA((UAx, UAy))
    VA = params["V"]
    VAx = decode_p2(VA["x"])
    VAy = decode_p2(VA["y"])
    VA = EA((VAx, VAy))

    EAB, _ = prime_power_isogeny(UA + sB*VA, lB, eB)

    shared = EAB.j_invariant()

    sc.recvuntil(b"shared key is: ")
    alice_shared = F(sc.recvline().decode().strip())
    res = alice_shared != shared

    known += (res << i)

    print(i, bin(known))

    sc.close()
    if i % 8 == 7:
        print(int.to_bytes(int(known), (i+1) // 8, "big"))

    i += 1
```

`prime_power_isogeny`が遅く、1時間とちょっとぐらいかかるが無事に求められる。

## 次回予告

次回は[pwnyaa](https://twitter.com/pwnyaa)さんによる「猫たちと学ぶ量子コンピュータ」の記録と復習を書く予定ですが、160ページに渡る膨大な資料が降ってきたのでいつ終わるかはわかりません。

当日の成果としては、テンソル積やブラケット記法から始まり、基本的なゲートの定義を学んでから[Bsides Ahmedabad CTF 2021](https://github.com/zer0pts/Bsides-Ahmedabad-CTF-2021)のqunknownという問題を解きました。量子テレポーテーション(正確にはその応用であるゲートテレポーテーションらしい)を実装すると解けるという非常に教育的な問題だったので、しっかりWriteupを書こうと思います。

そんな調子で残りの講義の復習と記録を書いていく予定ですが、自分の講義(ペアリングについてCTFの出題例を元に講義をした)については参加記として書いても特に意味が無いので[CTF Advent Calendar 2022 - Adventar](https://adventar.org/calendars/7550?utm_source=pocket_saves)の2022/12/22に枠を取って概要と扱った問題の解説を書こうと思います。ちなみに、この参加記を書いている現在はまだ最終日の分が空いているので誰か埋めてください。

---

[^1]: LLLのCTFでの使い方を初めて学んだのも、楕円曲線に対する攻撃をまとめて学んだのも、Coppersmith's Attackの実装をする気になったのも全部yoshicampの参加記が発端だった

[^2]: 直観的には$l$-同種写像同士の合成は次数が$l^2$になるように、最終的に$e$回合成すると$l^e$-同種写像になる、みたいな理解をしている。

[^3]: では、SIDHが破られたのはこの問題が難しいとする仮定が破られたのかというとそうではなく、SIDHでは他にも多くの情報$\phi_A(P_B)$等を開示していたせいで破られたらしい

[^4]: 実はこれは群になる

[^5]: 前節のSIDHスクリプトは$s_A$を毎度変えているので、これを固定の値にしたもの
