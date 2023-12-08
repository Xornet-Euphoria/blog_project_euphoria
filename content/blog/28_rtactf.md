+++
title = "Writeup: RTACTF (Crypto)"
date = 2021-12-19
description = "SECCON電脳会議(だっけ?)の裏側で行われていたRTACTFで公開されていた問題の内、Cryptoを全部解いたのでWriteupを書きます。"

[taxonomies]
tags = ["CTF", "Crypto", "RSA"]
+++

SECCON電脳会議(だっけ?)の裏側で行われていたRTACTFで公開されていた問題の内、Cryptoを全部解いたのでWriteupを書きます。

<!-- more -->

本当は取り組む予定が無かったのですが、起きたらチームのDiscord鯖で「@Xornet 16:30からcryptoはじまるってよ」という直々のリプライを貰ったのと、二度寝出来なかった上にPCを付けたらちょうど始まる寸前だったので取り組みました。

## Links

- [配信URL](https://www.youtube.com/watch?v=VXaROnAmAiY)
- [会場(跡地)](https://speedrun.seccon.jp/)
- [kurenaifさんの配信](https://www.youtube.com/watch?v=tDkNKz0qMW4)

<!--
## Table of Contents

- [Links](#links)
- [Table of Contents](#table-of-contents)
- [RTA特有の準備](#rta特有の準備)
- [Sexy RSA](#sexy-rsa)
- [Proth RSA](#proth-rsa)
  - [`k1 + k2`の導出](#k1--k2の導出)
  - [`k1 + k2`と`k1 * k2`から復号](#k1--k2とk1--k2から復号)
- [Leaky RSA](#leaky-rsa)
- [Neighbor RSA](#neighbor-rsa)
- [追記](#追記)
-->

## RTA特有の準備

Writeupの前に、今回はspeedrunだったので次の事を意識しました。CryptoだとPythonでソルバを書くのでだいたいPythonの事情です。

- モジュールを指定せず、`from <package> import *`を使う
- 最初にモジュールを読み込むだけの処理を書いたテンプレコードを作業用ディレクトリにおいておく
- PythonインタプリタとSageインタプリタは起動しておく、もちろん必要なモジュールは読み込んでおく
- `if __name__ == "__main__":`を書かない(むしろライブラリでも無いのに普段も書く必要あるか?って思った)

## Sexy RSA

次のような暗号化スクリプトとその実行結果が与えられました。

```python
from Crypto.Util.number import getPrime, isPrime
import os

def getSexyPrime(n=512):
    # Sexy prime: https://en.wikipedia.org/wiki/Sexy_prime
    while True:
        p = getPrime(n)
        if isPrime(p+6):
            return p, p+6

if __name__ == '__main__':
    # Plaintext (FLAG)
    m = int.from_bytes(os.getenv("FLAG", "FAKE{sample_flag}").encode(), 'big')

    # Generate key
    p, q = getSexyPrime()
    n = p * q
    e = 65537

    # Encryption
    c = pow(m, e, n)

    # Information disclosure
    print(f"n = 0x{n:x}")
    print(f"e = 0x{e:x}")
    print(f"c = 0x{c:x}")

```

`getSexyPrime`を見ればわかるように非常に近い2つの素数から`n`が作られているのでフェルマー法を使うだけ。自前ライブラリに実装があるので非常に楽でした。

```python
from xcrypto import *
from Crypto.Util.number import *

n = 0xe72988e811f04091c3291ac28f1e8332193187f3dc5af01579c36badb06671aa9a9543aa07eba8cdab36d787f1ff98a06db995c43cd5c63581ce050e0b9ba856634dabfaf8c7f271fbd026edd6ea1257b16013a526e0581a688cc6a335e7ee4c1b0633f0532d3d0824824195b6b249c70cf0e458609efc01a6575f084e6de53b
e = 0x10001
c = 0x6fadd5d7095bd6f45de69bb4e76080e0ea5f8c5a159de10663133e585b71ae580b99b3e0a8e047a9c51c8091a6b33b01c9ab95668794c3acfb084e939a04cb151757c3b2522da99e03f83e205c7c701066d69b120ca17fcf59061c078d9099e5f4bf6dd6dab206418527035f2c1096861c2896327977ac88c2728faa7504d879


p,q = fermat_method(n)
m = dec_pq(c,p,q,e)

print(long_to_bytes(m))

```

この問題は141.78secで解いて現時点のスコアボードでは2位でした。それをチームDiscordで伝えたら「匿名やめろ」(寝起きで何も考えず"anonimasu"という名前にしていた)みたいな事を言われてしまったのでアカウントを作り直し次の問題から".X."で出る事にしました(".V."で出ているチームメイトが居たので)。

## Proth RSA

次のようなスクリプトとその実行結果が与えられました。

```python
from Crypto.Util.number import getRandomInteger, getPrime, isPrime
import os

def getProthPrime(n=512):
    # Proth prime: https://en.wikipedia.org/wiki/Proth_prime
    while True:
        k = getRandomInteger(n)
        p = (2*k + 1) * (1<<n) + 1
        if isPrime(p):
            return p, k

if __name__ == '__main__':
    # Plaintext (FLAG)
    m = int.from_bytes(os.getenv("FLAG", "FAKE{sample_flag}").encode(), 'big')

    # Generate key
    p, k1 = getProthPrime()
    q, k2 = getProthPrime()
    n = p * q
    e = 65537
    s = (k1 * k2) % n

    # Encryption
    c = pow(m, e, n)

    # Information disclosure
    print(f"n = 0x{n:x}")
    print(f"e = 0x{e:x}")
    print(f"s = 0x{s:x}")
    print(f"c = 0x{c:x}")

```

気合で計算式を立てると次のような関係がある事がわかりました。

$$
N = (4s + 2(k_1 + k_2) + 1)\cdot 2^{1024} + (2(k_1 + k_2) + 2) \cdot 2^{512} + 1
$$

この式を{{katex(body="k_1 + k_2")}}が変数の方程式とみなすとこれを求めることが出来ます。

また、既に{{katex(body="k_1k_2")}}は与えられている({{katex(body="n")}}で法が取られていますが、明らかに{{katex(body="k_1k_2 \lt n")}}なので関係ない)ので、{{katex(body="k_1 + k_2")}}を求めることが出来れば2次方程式の解と係数の関係を利用してどちらも求めることが出来ます。

というわけで{{katex(body="k_1, k_2")}}が求められたので後は{{katex(body="p,q")}}を求めて復号するだけです。

なお、RSAの2つの素因数、{{katex(body="p,q")}}で似たこと({{katex(body="p+q, pq")}}からこの2つを求める)をする問題がよく出て、それを解くための関数を自作ライブラリに入れていたので{{katex(body="k_1 + k_2")}}求めてからは速かったです。

### `k1 + k2`の導出

```python
from Crypto.Util.number import *


n = 0xa19028b5c0e77e19fc167374358aa346776e6c20c27499505be59c83ea02014e97af631ba0ccbab881313818fd323c15c82dad8793220ba6679ec4b38787e04d0c1fff0880e04423ea288e443660c63a1607532e47dbaad421723d0546c208447f701cd7e9ee1bb43774d132abbb2e91bf50b67be40ed854dbe6c3071ca3ae3307ac03abd76f74e506594106a22795d4b7938611301248a9957e1a637538a9169cf38daf5d60ffc05ae32ea7e638e16d790ffeebfff655a645c99a513616d3ce00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001
e = 0x10001
s = 0x28640a2d7039df867f059cdd0d62a8d19ddb9b08309d265416f96720fa808053a5ebd8c6e8332eae204c4e063f4c8f05720b6b61e4c882e999e7b12ce1e1f812c11cfed72a5c33cfb8f3d34f650e4c19579cf34745f2588aa2fd08a8746257cb789f23ca232346fcf72468a2b160934911902de3f90620aba5874a2d79a33699
c = 0x4595c3c923bd191ba07456611f80e656a197ff528a031e2952adedda532b1fa2caef719c929132a3cdf06d0e55e6a00f7eb1f189a614b26759916ec42f83579a75ab5948186769a1a936b019466f918f29e32852675c464b7f0797c6fdc55efcd54fbe2083761b1df3dde0b9a9a35b96e3b216c54770b444b1f02525f0268c44483c6e84a781fe9111e6912130d69f462c519873043d44e4a3f1f938491feeb591b5831d0abe7399bc87244576decaf2925f287d3c2bb4061d560c919d820e364744f2322c7efd37d42563842bcf9b1d6b46218694dcd49758d311c6896e38cf2b55c7114d78cfdfaeba74720ecf30d9133034799b9735e26ec913cc9f26bb0a

R.<x> = PolynomialRing(ZZ)
f = (4 * s + 2*x + 1) * 2^1024 + (2 * x + 2) * 2^512 + 1 - n
x = f.roots()[0][0]

print(x)
```

### `k1 + k2`と`k1 * k2`から復号

```python
from xcrypto import *
from Crypto.Util.number import *


n = 0xa19028b5c0e77e19fc167374358aa346776e6c20c27499505be59c83ea02014e97af631ba0ccbab881313818fd323c15c82dad8793220ba6679ec4b38787e04d0c1fff0880e04423ea288e443660c63a1607532e47dbaad421723d0546c208447f701cd7e9ee1bb43774d132abbb2e91bf50b67be40ed854dbe6c3071ca3ae3307ac03abd76f74e506594106a22795d4b7938611301248a9957e1a637538a9169cf38daf5d60ffc05ae32ea7e638e16d790ffeebfff655a645c99a513616d3ce00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001
e = 0x10001
s = 0x28640a2d7039df867f059cdd0d62a8d19ddb9b08309d265416f96720fa808053a5ebd8c6e8332eae204c4e063f4c8f05720b6b61e4c882e999e7b12ce1e1f812c11cfed72a5c33cfb8f3d34f650e4c19579cf34745f2588aa2fd08a8746257cb789f23ca232346fcf72468a2b160934911902de3f90620aba5874a2d79a33699
c = 0x4595c3c923bd191ba07456611f80e656a197ff528a031e2952adedda532b1fa2caef719c929132a3cdf06d0e55e6a00f7eb1f189a614b26759916ec42f83579a75ab5948186769a1a936b019466f918f29e32852675c464b7f0797c6fdc55efcd54fbe2083761b1df3dde0b9a9a35b96e3b216c54770b444b1f02525f0268c44483c6e84a781fe9111e6912130d69f462c519873043d44e4a3f1f938491feeb591b5831d0abe7399bc87244576decaf2925f287d3c2bb4061d560c919d820e364744f2322c7efd37d42563842bcf9b1d6b46218694dcd49758d311c6896e38cf2b55c7114d78cfdfaeba74720ecf30d9133034799b9735e26ec913cc9f26bb0a
x = 13608713745476712252761352055448779474808135387401125423929142562471060808644950728239074888981889645058591842947981527031995119707968867615326111808580070


k1,k2 = p_plus_q_to_pq(s,x)
p1 = (2*k1 + 1) * (1<<512) + 1
p2 = (2*k2 + 1) * (1<<512) + 1

print(long_to_bytes(dec_pq(c,p1,p2,e)))
```

この問題は654.47secで解いて現時点のスコアボードでは4位でした。

## Leaky RSA

次のようなスクリプトとその実行結果が与えられました。

```python
from Crypto.Util.number import getPrime, isPrime, inverse
import os

if __name__ == '__main__':
    # Plaintext (FLAG)
    m = int.from_bytes(os.getenv("FLAG", "FAKE{sample_flag}").encode(), 'big')

    # Generate key
    p = getPrime(600)
    q = getPrime(500)
    n = p*p*q*q
    e = 65537
    s = ((p**3 - 20211219*q) * inverse(p*p+q*q,n)) % n # tekitou (ha?)

    # Encryption
    c = pow(m, e, n)

    # Information disclosure
    print(f"n = 0x{n:x}")
    print(f"e = 0x{e:x}")
    print(f"c = 0x{c:x}")
    print(f"s = 0x{s:x}")

```

ヒントパラメータとなっている`s`に注目すると次のような関係がある事がわかります。

$$
s(p^2 + q^2) \equiv p^3 - 20211219\cdot q \mod (p^2q^2)
$$

ここで合同式を使わない形にしてから{{katex(body="p")}}で法を取ってみる事を考えます。すると次のようになります。

$$
sq^2 + 20211219 \cdot q \equiv 0 \mod p
$$

さて、ここでCoppersmith's Attackに関して忘れがちな事実として、法{{katex(body="N")}}の因数を法とした場合でも解を求められるというのがあります。詳しくは次を参照してください。

- [Dense univariate polynomials over \(\ZZ/n\ZZ\), implemented using NTL — Sage 9.4 Reference Manual: Polynomials](https://doc.sagemath.org/html/en/reference/polynomial_rings/sage/rings/polynomial/polynomial_modn_dense_ntl.html#sage.rings.polynomial.polynomial_modn_dense_ntl.small_roots)
- [SageMathを使ってCoppersmith's Attackをやってみる - ももいろテクノロジー](https://inaz2.hatenablog.com/entry/2016/01/20/022936): 「素数pの上位bitまたは下位bitがわかっている場合」の節

これをそのまま使います。パラメータの調整に7割ぐらいの時間を割きましたが、`q = getPrime(500)`なので`X=2^500`にしたら求められました(それまで`int(N^1/4)`とかしてました)。

```python
from Crypto.Util.number import *

n = 0x2ac1fcbbf63ffeade11cd2c57c37db18d96d52e433bd9034d4eac2c269ea49a81e5ac41fb631523bb5983adc6fc939c073c13d8a3a42a06accf5a9c304fc444508a8b5833b5431e9af7007bb216c510c62a97eb1fe380bf155b3e497c7d70c2bb921f97eec61e9e9ac7b5d71e47876d20cbfb1a0732e29ec6872041eb67e0ccd39d7b6429bda1581537dda95e79d3aad4df072beada1c72a4ffd86db91918ec9db44ab9c4bebf387ccc1ce7b2540b0d595a4c11823cdbcd8850bd3b666b4a08bd69de515afecc75b283ae47fbf3af6f034f3b0f7848dec935ba8b97e36d2d0a9208df63610cf8825fb729aacaa4c119d0b4c5e230e080d7633f145d22eb06b917fe632c01a373b1c4c8a741bea1d5dd98003e9
e = 0x10001
c = 0xe50a858f715238a9ab44dfd691f6e5ced84e74115e003e31a98b324cf9e8bc9cfe08065f2538cff519e035566b4080742139062e672a0ad3196275cb121ea837de2808f99958bcfe58d1c8996f291412220d01fe65fbf18611b348407b2e2db45b2adcc341926c6d76a9d08fc77db0fedef78cec9e4b881812e60c015c1005dfd0b9408cb3c6f9f98332f165acc3ae98ef97f2a1d98524fe240d3351676ed84ddb73283a6d3efc40bbd466fe3532e579eb9adf07ebbc49af71fb22934a75a69a538eca0fd4e2a5b617abb361a64c553985950dd5201ac7c631580c8bb27d795a196d584ae7c7478bdc1b5ff531ff88e984bceb1e26cf9793f99a11287555d5d2d2a13e1171f77bf8491d8dfa297e9cd6d4b7d
s = 0x14c0af71a961be72e2d4e5ee06337cde2034db1d920f4476e3a3371c8a35e7ba8efabf5c8e8ff86e7297156c4fde5bdc7aabe1516a46c554236104022eb4544f1d7fcb80279595dfe0527bcc373909ce7cc0965ece5ff76b7ee9a5cc31a1b567ed3ddd2364bb596e3c41e4fffb5974f71e788da5c21598e9c6dc32bca162026ba3c410bb1c5c9d5bed4c3b97e3cacbd7b6693f29c74b0756381b658efaa757d448f62a48fbdb06604525222aa51797a1a1e43af4b0c221deef47f84bb5bfa1480cd31242c3d7fba21bdf487709853879dcea284e44cb5ee1a02c558a29740a44e39c7ee3a97ab4805d21cb90b596bd86c51f4e0f783701da73c66f5a4c67d989bb2dba2b8a55a697eb187cc181fc8ce54de370

_n = 5551147074848155930796050384544822447377526648232033530446192334432427578114873676436396482644095477492498494991882127338487026648146480464368791975434229054930911137198369948451442120787879366443902996524188943773888054277864045995982527412755849602216471555099162784683545765685279609778562682160512693299837447709989681732602323
a = 20211219

PR.<q> = PolynomialRing(Zmod(n))

f = s*q^2 + a*q
f = f.monic()
roots = f.small_roots(beta=0.27, X=2**500, epsilon=1/50)
q = roots[1]

p = _n // int(q)
print(p,q)

```

素因数分解が出来た後は自明なので割愛します。

この問題は2776.51secで解いて現時点のスコアボードでは5位でした。チームのWeb担当のArkに圧倒的遅さで負けてしまったのでCrypto担当をやめようと思います。そしてCryptoしかやっていないので実質CTF引退です。2年半楽しかったです。ありがとうございました。

## Neighbor RSA

次のようなスクリプトとその実行結果が与えられました。

```python
import os

# Plaintext (FLAG)
plaintext = os.getenv("FLAG", "FAKE{sample_flag}").encode()
plai  = plaintext[:len(plaintext)//2]
ntext = plaintext[len(plaintext)//2:]
m1 = int.from_bytes(plai  + os.urandom(128), 'big')
m2 = int.from_bytes(ntext + os.urandom(128), 'big')

# Generate key
e = 65537
p = random_prime(1<<2048)
q = random_prime(1<<512)
r = random_prime(1<<512)
n1 = p * q
n2 = next_prime(p) * r
assert m1 < n1 and m2 < n2

# Encryption
c1 = pow(m1, e, n1)
c2 = pow(m2, e, n2)

# Information disclosure
print(f"e = {hex(e)}")
print(f"n1 = {hex(n1)}")
print(f"n2 = {hex(n2)}")
print(f"c1 = {hex(c1)}")
print(f"c2 = {hex(c2)}")

```

2つの公開鍵{{katex(body="n_1, n_2")}}の構成方法を見るとわかるようにその素因数に近い2つの数`p`, `next_prime(p)`が使われています。ということはApproximate GCDが使えそうです。

Approximate GCDについては、適用できる状況以外に正直よくわかっていないので詳しくは次の資料をご覧ください。

- [Approximate GCDとして解く問題 - RCTF 2021 Uncommon Factor 2 / Midnightsun CTF 2021 Finals Flåarb.tar.xz writeup - ふるつき](https://furutsuki.hatenablog.com/entry/2021/09/23/122340)
- [The Approximate GCD Problem – malb::blog](https://martinralbrecht.wordpress.com/2020/03/21/the-approximate-gcd-problem/)
- [Lattices and Approximate GCD](https://www.math.snu.ac.kr/~jhcheon/2013.1.31.pdf)

これらを読みながらソルバを書いて終わりです。ふるつきさんの記事の2つ目のソルバをほとんどパクりました。

```python
e = 0x10001
n1 = 0xa8ed020c3dd125d503bf124052d643ba1405f2c349244122140e79e7d2244304a1590762c61ac83900c2aced76007b2e3f320464fd51fcfad167ebdc87e69329230869e0a3e153b44ed3b04bfe94174bc8b5ee1a3fa8036b6b9e834666aa07229a431b477e589d94f9a4cfed25b195215b0c694b86e874413b8a00cb064809c8e3677632cde9b43b87a0b812c2024b0c821b5c10764fd4de2d18af55d897d94aeded80b71e36fd73014f75641a8c5b38b36faa020e7cf1327a707bb7d42503bcc28768ef184d66b9ba16efd019b68268885a2da302cd326e78b1d473bcf7cd62442ccd25dc85d23aeb5408922b6b00f13584bea394f1bca4cc431f3c29c5d98ec1683453cc0c526abe4aec08781c7a53f50f2047b4995b9bea6a7a9f6b5425b29be6e867764efaa050799f716af78273041372cfe4f3c88a62329f6f1feff99
n2 = 0x16ea1bde86ea11cdec196a9173258efca235da66f8e3d5437e39e1b2e2574dd3f93d65104ca0225d6119519ae9ea9c035e0f85f02212c0992d0705723fa8b97ed6cff860c4d8fb65f0214a0047feca64e662dcbf025fff47590305e90e5d070d39871880828f5e960ab2ef330129ed5752c3b4debe827376a632b06487740fff4b622a88de23649e3e6993cd332b0284b84eb8765d58527209cc202c89d479421131a2f64ae517ee1e62e6c0f329c306569e427113ec6a8b9d96d73e95580d3a33f6add681f9a9156f0681eb1804183dfa8cebbe921d2fb1d43b256f727d46c5859cc5229f7e555ad25397e5cd14620ebbaefa0a0a520bada3ef8b115481734242af6befbd9b069d4a03281094c0f4aca4e6fdcbe2558b104fc2b383e1c70f0e5a07d1a623f9fc2309ca1d09b69aa1869e280fbc50de2adbada7ea545743b12b
c1 = 0x690e49037fee7649033ffaaa71e4730d2d7143fab97beb22e2afdf6eca449cad3f95b60295f592e7e84833e08b3468d61a34c1d1123f4c683c79d68bbe27dd0af203fc50ef7ebe98b1bc1221918470f058a8fb7645eacb569931835bd7f80494dbb67fbaa592ec19d9b4930c787a2ce1267f8088229b5031e710d6cd5720756923ccb64444939a0f09a51c87488650d4d02551fd4ed7a2fd248825ec34c5df8b6077a6d0d75c5832f9140420c92d3d00cf51e3b0665f5a6d031cb369ddebbb5ce77f2176cd12bb0add5aeda6ae88c4ceade0c1fd0ff3960d3ee36a0c6455ae3027f33e660663d0e2298654e19e8c8a06b4de991fac3b4c1673825b3d9f8f5c675f920a7d137f85ba723bf741321904e0c3c601f5c18d02e1e5b7b118e62e91a7926a9b1eda3cc53e2a6cbc95553e1990ec3f6cceddf283410d6e6849a26f89b
c2 = 0x5c4c7dce82753a68dcdbcdce9af52c9b7af2f561c08b8e23b27c6145d4c3df29d498303bee1bd29829a2e0ae9faaf243b387c39d69daccba07dace7bb420115ffaa69f89a3ea4e1ef0e08eb19043e012a090b79e51d6ae8446ca76e88abe5adbdbe25a731d7ee9aa333a84447edafbc360b505ff293c751571c6bf29dee99fdc443b756f182eb588b4a03de3d35dc4f23736d7239cfbd0ca13fa7b234bc4064a2053ab0045f4833250c8c9de91798502b09d4312ee52f3dc5229dfcb73b42f7c3440932839e6e790bb0db1788fbd7c60365121bbe3858ecedd3d48261d081c380e7ddf6ca570c13cc89c0af2011b4978b22d5456d1122dabd7b2068ab30e301a674809732daede77a27ae13e1bc4779e15d51210f6c10be159907ec1a59bfaf8db6cf290a348f734fd88e3c2b7df6bda84665b810cfe55bc3645d8d118c9172

k = 2**512
mat = [
    [k, 0, n1],
    [0, k, -n2]
]

mat = Matrix(mat)
LLLed = mat.LLL()

for b in LLLed:
    zs = [abs(x // k) for x in b]
    for q in zs:
        for n in [n1, n2]:
            g= (gcd(n,q))
            if g != 1:
                print(g,q)
```

これを動かすとなんか数字が出た上に何故か`n1,n2`の素因数だったので後は復号するだけです。

```python
from xcrypto import *
from Crypto.Util.number import *


e = 0x10001
n1 = 0xa8ed020c3dd125d503bf124052d643ba1405f2c349244122140e79e7d2244304a1590762c61ac83900c2aced76007b2e3f320464fd51fcfad167ebdc87e69329230869e0a3e153b44ed3b04bfe94174bc8b5ee1a3fa8036b6b9e834666aa07229a431b477e589d94f9a4cfed25b195215b0c694b86e874413b8a00cb064809c8e3677632cde9b43b87a0b812c2024b0c821b5c10764fd4de2d18af55d897d94aeded80b71e36fd73014f75641a8c5b38b36faa020e7cf1327a707bb7d42503bcc28768ef184d66b9ba16efd019b68268885a2da302cd326e78b1d473bcf7cd62442ccd25dc85d23aeb5408922b6b00f13584bea394f1bca4cc431f3c29c5d98ec1683453cc0c526abe4aec08781c7a53f50f2047b4995b9bea6a7a9f6b5425b29be6e867764efaa050799f716af78273041372cfe4f3c88a62329f6f1feff99
n2 = 0x16ea1bde86ea11cdec196a9173258efca235da66f8e3d5437e39e1b2e2574dd3f93d65104ca0225d6119519ae9ea9c035e0f85f02212c0992d0705723fa8b97ed6cff860c4d8fb65f0214a0047feca64e662dcbf025fff47590305e90e5d070d39871880828f5e960ab2ef330129ed5752c3b4debe827376a632b06487740fff4b622a88de23649e3e6993cd332b0284b84eb8765d58527209cc202c89d479421131a2f64ae517ee1e62e6c0f329c306569e427113ec6a8b9d96d73e95580d3a33f6add681f9a9156f0681eb1804183dfa8cebbe921d2fb1d43b256f727d46c5859cc5229f7e555ad25397e5cd14620ebbaefa0a0a520bada3ef8b115481734242af6befbd9b069d4a03281094c0f4aca4e6fdcbe2558b104fc2b383e1c70f0e5a07d1a623f9fc2309ca1d09b69aa1869e280fbc50de2adbada7ea545743b12b
c1 = 0x690e49037fee7649033ffaaa71e4730d2d7143fab97beb22e2afdf6eca449cad3f95b60295f592e7e84833e08b3468d61a34c1d1123f4c683c79d68bbe27dd0af203fc50ef7ebe98b1bc1221918470f058a8fb7645eacb569931835bd7f80494dbb67fbaa592ec19d9b4930c787a2ce1267f8088229b5031e710d6cd5720756923ccb64444939a0f09a51c87488650d4d02551fd4ed7a2fd248825ec34c5df8b6077a6d0d75c5832f9140420c92d3d00cf51e3b0665f5a6d031cb369ddebbb5ce77f2176cd12bb0add5aeda6ae88c4ceade0c1fd0ff3960d3ee36a0c6455ae3027f33e660663d0e2298654e19e8c8a06b4de991fac3b4c1673825b3d9f8f5c675f920a7d137f85ba723bf741321904e0c3c601f5c18d02e1e5b7b118e62e91a7926a9b1eda3cc53e2a6cbc95553e1990ec3f6cceddf283410d6e6849a26f89b
c2 = 0x5c4c7dce82753a68dcdbcdce9af52c9b7af2f561c08b8e23b27c6145d4c3df29d498303bee1bd29829a2e0ae9faaf243b387c39d69daccba07dace7bb420115ffaa69f89a3ea4e1ef0e08eb19043e012a090b79e51d6ae8446ca76e88abe5adbdbe25a731d7ee9aa333a84447edafbc360b505ff293c751571c6bf29dee99fdc443b756f182eb588b4a03de3d35dc4f23736d7239cfbd0ca13fa7b234bc4064a2053ab0045f4833250c8c9de91798502b09d4312ee52f3dc5229dfcb73b42f7c3440932839e6e790bb0db1788fbd7c60365121bbe3858ecedd3d48261d081c380e7ddf6ca570c13cc89c0af2011b4978b22d5456d1122dabd7b2068ab30e301a674809732daede77a27ae13e1bc4779e15d51210f6c10be159907ec1a59bfaf8db6cf290a348f734fd88e3c2b7df6bda84665b810cfe55bc3645d8d118c9172

r = 1259963660091541187817462040620314994344343131080173043489698470231064597945784163412609817706097787609898931496802354115594752366012274742210528613462711
q = 580528973937944529052546677517025303586176665627253516520058504529646380025101690766834709825855277812213856408695312736525990791127903767963372464351853

p1 = n1 // q
p2 = n2// r

m1 = dec_pq(c1, p1, q, e)
m2 = dec_pq(c2, p2, r, e)

print(long_to_bytes(m1))
print(long_to_bytes(m2))
```

この問題は761.46secで解いて現時点のスコアボードでは3位でした。提出した時は1位だったんですが、その後に解いた人が数秒速かったらしく抜かれました。そして更に時間が更新されて3位になりました。悔しい。

ちなみにこの問題はCoppersmith's Attackでも解けるらしく、AGCDを知らなくても解けたらしいです。非Crypto勢でそのケースを数名観測しており「CTFプレイヤー怖いな～」という気持ちになりました。

## 追記

(2021/12/20 追記)  
[rkm0959](https://twitter.com/rkm0959)さんが[全部の問題を瞬殺して大幅に記録を塗り替えた](https://twitter.com/ptrYudai/status/1472577623440379907)事で上記問題の順位がどれも1つ落ちました。彼をナーフしてください。
