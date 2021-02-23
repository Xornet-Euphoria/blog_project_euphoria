+++
title = "行列の離散対数問題を解く: Union CTF - neo-classical key exchange"
date = 2021-02-24

[taxonomies]
tags = ["CTF", "Writeup", "Crypto", "DLP"]
+++

先日ちょっとだけ取り組んだUnion CTFで行列でDH鍵共有をしている問題が出て結構面白かったのでそのWriteupを兼ねて行列の離散対数問題について書きます。

なお、この問題は当日、私がオンライン飲み会に興じている最中にチームメイトが解いていたのをCTF終了後に解き直したものなので私が加点した問題ではありません。

<!-- more -->

## Prerequisite

下記事項を知っている読者を対象としています。

- 離散対数問題と典型的な解き方
  - Pohlig-Hellmanアルゴリズム(今回の問題に直接関係はしない)
- 線形代数に関する知識
  - 対角化
  - ジョルダン標準形

## 対角化可能な場合

Writeupの前に対角化可能な行列の場合を考える。また、以下では各要素が{{katex(body="\mathbb{F}_p")}}の要素であるような行列を考える。ただし{{katex(body="p")}}は素数とする。

問題設定としては行列{{katex(body="G")}}とそれを{{katex(body="k")}}乗した行列{{katex(body="A \coloneqq G^k")}}が与えられてこの2つから{{katex(body="k")}}を求めるという問題である。

ここで{{katex(body="G")}}が対角化可能な場合は{{katex(body="G = PBP^{-1}")}}と表すことが出来、これを両辺{{katex(body="k")}}乗すると次のようになる。

$$
G^k = A = PB^kP^{-1}
$$

ここで{{katex(body="B")}}は対角行列であり、{{katex(body="B^k")}}は対角成分が固有値の{{katex(body="k")}}乗である対角行列になる。ここで対角化によって{{katex(body="P")}}は判明し、{{katex(body="A")}}も分かっている為、{{katex(body="B^k = P^{-1}AP")}}によって{{katex(body="B^k")}}が判明する。

すると固有値を{{katex(body="\lambda_i")}}とおくと、{{katex(body="B^k")}}の対角成分{{katex(body="\lambda_i^k \bmod p")}}から{{katex(body="k")}}を求めよ、という問題になるためいつもの{{katex(body="\mathbb{Z}/p\mathbb{Z}^*")}}上の離散対数問題に帰着する。

つまり{{katex(body="p")}}が安全素数でないならPohlig-Hellmanアルゴリズムが有効な為、このような行列が対角化可能なら離散対数問題は解けてしまう事になる。

## 対角化不可能な場合(Writeupはここから)

今回扱うUnion CTF - neo-classical key exchangeでは{{katex(body="G")}}の対角化は出来ない。そこで登場するのがジョルダン標準形である。

ちなみに{{katex(body="p")}}も安全素数であるため、仮に出来たとしてもPohlig-Hellmanアルゴリズムを使うのは難しい(対角化不可能なことを知るより先にこっちからジョルダン標準形が出てきた)。

### Challenges

次のようなスクリプトとその実行結果をくれる。

```python
import os
from hashlib import sha1
from random import randint
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

FLAG = b"union{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}"

def list_valid(l):
    x = l // 2
    checked = set([x])
    while x * x != l:
        x = (x + (l // x)) // 2
        if x in checked: return False
        checked.add(x)
    return True

def list_iter(n):
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x

def list_mul(l1,l2,p):
    X, Y = len(l1), len(l2)
    Z = list_iter(X)
    assert X == Y
    assert list_valid(X)
    l3 = []
    for i in range(Z):
        for j in range(Z):
            prod_list = [x*y for x,y in zip(l1[Z*i:Z*(i+1)], l2[j::Z])]
            sum_list = sum(prod_list) % p
            l3.append(sum_list)
    return l3

def list_exp(l0, e, p):
    exp = bin(e)[3::]
    l = l0
    for i in exp:
        l = list_mul(l,l,p)
        if i == '1':
            l = list_mul(l,l0,p)
    return l

def gen_public_key(G,p):
    k = randint(2,p-1)
    B = list_exp(G,k,p)
    return B,k

def gen_shared_secret(M,k,p):
    S = list_exp(M,k,p)
    return S[0]

def encrypt_flag(shared_secret: int):
    # Derive AES key from shared secret
    key = sha1(str(shared_secret).encode('ascii')).digest()[:16]
    # Encrypt flag
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(FLAG, 16))
    # Prepare data to send
    data = {}
    data['iv'] = iv.hex()
    data['encrypted_flag'] = ciphertext.hex()
    return data

p = 64050696188665199345192377656931194086566536936726816377438460361325379667067
G = [37474442957545178764106324981526765864975539603703225974060597893616967420393,59548952493843765553320545295586414418025029050337357927081996502641013504519, 31100206652551216470993800087401304955064478829626836705672452903908942403749, 13860314824542875724070123811379531915581644656235299920466618156218632047734, 20708638990322428536520731257757756431087939910637434308755686013682215836263, 24952549146521449536973107355293130621158296115716203042289903292398131137622, 10218366819256412940642638446599581386178890340698004603581416301746386415327, 2703573504536926632262901165642757957865606616503182053867895322013282739647, 15879294441389987904495146729489455626323759671332021432053969162532650514737, 30587605323370564700860148975988622662724284710157566957213620913591119857266, 36611042243620159284891739300872570923754844379301712429812256285632664939438, 58718914241625123259194313738101735115927103160409788235233580788592491022607, 18794394402264910240234942692440221176187631522440611503354694959423849000390, 37895552711677819212080891019935360298287165077162751096430149138287175198792, 42606523043195439411148917099933299291240308126833074779715029926129592539269, 58823705349101783144068766123926443603026261539055007453105405205925131925190, 5161282521824450434107880210047438744043346780853067016037814677431009278694, 3196376473514329905892186470188661558538142801087733055324234265182313048345, 37727162280974181457962922331112777744780166735208107725039910555667476286294, 43375207256050745127045919163601367018956550763591458462169205918826786898398, 21316240287865348172884609677159994196623096993962103476517743037154705924312, 7032356850437797415676110660436413346535063433156355547532408592015995190002, 3916163687745653495848908537554668396996224820204992858702838114767399600995, 13665661150287720594400034444826365313288645670526357669076978338398633256587,23887025917289715287437926862183042001010845671403682948840305587666551788353]
A,a = gen_public_key(G,p)
B,b = gen_public_key(G,p)
assert gen_shared_secret(A,b,p) == gen_shared_secret(B,a,p)

shared_secret = gen_shared_secret(B,a,p)
encrypted_flag = encrypt_flag(shared_secret)

print(f"Alice's public key: {A}") 
print(f"Bob's public key: {B}")
print(f"Encrypted flag: {encrypted_flag}")




```

`list_.*`系の関数はどれも行列に関するものであって次のようになっている。

- `list_valid()`: リストの長さが平方数かを確認 -> 正方行列の形として表す事が出来るかを確かめている
- `list_iter()`: 平方根を導出 -> 正方行列として表した時のサイズを返す
- `list_mul()`: 行列積
- `list_exp()`: 行列のべき乗

これらの関数を使ってDH鍵共有が行われており、共有した値から鍵が作られてAESで暗号化されている。なお、各行列は5x5のサイズである。

### ジョルダン標準形のべき乗

ジョルダン標準形(やジョルダン細胞)が何かは他の資料に説明を譲るとしてこれのべき乗は簡単な形で表す事が出来る。例として2x2のジョルダン標準形{{katex(body="J")}}のべき乗を計算すると次のようになる。

$$
J^k = \left(
    \begin{matrix}
        \lambda & 1 \cr
        0 & \lambda
    \end{matrix}
\right)^k = \left(
    \begin{matrix}
        \lambda^k & k \lambda^{k-1} \cr
        0 & \lambda^k
    \end{matrix}
\right)
$$

この問題で出てくる`G`はある1つの固有値の重複度が2である事から2x2のジョルダン細胞を持つ行列{{katex(body="J")}}に行列{{katex(body="P")}}を用いて{{G = PJP^{-1}}}のように変換する事が出来る。

これを両辺{{katex(body="a")}}乗すると、{{katex(body="G^a = PJ^aP^{-1}")}}となり、左辺は`list_exp(G, a, p) = A`に等しくなる事から既知である。またこの変換によって{{katex(body="P")}}が判明するため、{{katex(body="J^a = P^{-1}AP")}}が既知である。

ここで{{katex(body="J^a")}}はジョルダン標準形のべき乗であるため、その形は比較的簡単に表せる。詳しくは[ここ](https://mathtrain.jp/matrixnjo)等を参考にしてほしいが、今回は5x5のジョルダン標準形の中に2x2のジョルダン細胞が含まれている事から先程の2x2の場合のような形がべき乗の中に現れて、重複している固有値を{{katex(body="\lambda")}}とおくと、{{katex(body="\lambda^a, a \lambda^{a-1}")}}が判明する。また、{{katex(body="\lambda")}}もジョルダン標準形へ変形する際に判明する。

したがって次のような式から{{katex(body="a")}}を導出出来る。

$$
a = \frac{a \lambda^{k-1} \times \lambda}{\lambda^{k-1}}
$$

これで行列の離散対数問題が解けたことになり、あとはスクリプトに記載の手順から復号手順が自明なので省略する。

## Flag

`union{high3r_d1m3n510ns_l0w3r_s3cur1ty}`

## 感想

面白かったです。{{katex(body="\mathbb{Z}/p\mathbb{Z}")}}以外の離散対数問題を解くのは新鮮でした。

以前、ある問題を行列の対角化を利用して解いた事があり、今回はそれの強化版だったので対角化の場合と併せて取り上げました。

Union CTF自体はリアルの都合であまり参加出来ませんでしたが、チームメイトが解いているのを見る感じだと楽しそうなCTFだったのでフルコミットしたかったです。他のCryptoの問題も楕円曲線の高さの増加度合いが大きいことを利用していた問題だったり、超同種写像Diffie-Hellmanの問題が出ていたりと数学が好きな人が作ったような問題が多かったので(特に超同種写像Diffie-Hellmanの問題は)しっかりと復習しようと思います。

ここまで読んでいただきありがとうございました。次もネタがちょっとだけあるので形になったら近いうちに投稿します。
