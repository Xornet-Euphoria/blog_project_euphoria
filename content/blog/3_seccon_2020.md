+++
title = "Writeup: SECCON 2020 Online CTF"
date = 2020-10-11

[taxonomies]
tags = ["CTF", "Writeup", "Crypto", "Rev", "SECCON"]
+++

SECCON 2020 Online CTFに参加して7位/579チーム(得点を入れた)でした。今回はBaby Crypto枠のThis is RSAとMedium(?) Rev枠のfixerを解いたのでそのWriteupになります。

<!-- more -->

## This is RSA

### 略解

p, qをランダム生成した数字を文字列として見てから各文字をASCIIコードに変換し、それを16進数とみなす形で生成しているので規則性がある。これをp, qの下の桁から探索していく事で確定することが出来る。

### 問題概要

下記ソースコードと出力結果が与えられる。

```ruby
require 'openssl'

def get_prime
  i = OpenSSL::BN.rand(512).to_s.unpack1('H*').hex
  OpenSSL::BN.new(i).prime? ? i : get_prime
end

p = get_prime
q = get_prime
n = p * q
e = 65537
m = File.read('flag.txt').unpack1('H*').hex
c = m.pow(e, n)

puts "N = #{n}"
puts "c = #{c}"
```

p, qの作り方が(慣れていないrubyなのもあって)やや読みにくいが頑張って読むと

1. まずランダムな512bitの数を生成する。
2. 次にそれを文字列にした後、`unpack1('H*')`で各文字を対応するバイトを示す文字列に変換する。
    - 具体的には`"1"`はバイトにすると`0x31`なので`"31"`に変換される
    - これを全文字で適用するので`"114514".unpack1('H*')`は`"313134353134"`になる。
3. この結果を16進数表記と見て数値に変換する。
4. それが素数なら返す、そうでなかったら素数になるまで繰り返す。

### 素因数分解

この生成方法によってp, qは次のようになる

$$ p = \sum_{i=0} (\mathrm{0x}30 + p_i) \times \mathrm{0x100}^i $$
$$ q = \sum_{j=0} (\mathrm{0x}30 + q_i) \times \mathrm{0x100}^j $$

この積であるnを計算すると次のようになる

$$ n = \sum_{i, j} \left(\mathrm{0x}900 + \mathrm{0x30}(p_i+q_j) + p_iq_j\right) \times \mathrm{0x}100^{i+j} $$

ここで0x100の0次の係数は $i = j = 0$ の時の $p_i, q_j$ にのみ依存する。$p_i, q_j$ はいずれも1桁の整数であるので組み合わせとして高々100通りの候補しかなく実際試してみると与えられたnと一致するp, qの組み合わせは対称性を考慮すると1つに定まる。

同様に0x100の1次の係数は $i+j = 1$ である $p_i, q_j$ と0次の係数を求めた際の繰り上がりに依存するのだが、仮に $i = j = 0$ における $p_i, q_j$ が決まっていれば $i, j = 1$ だけを考えれば良い事になる。

以下、$p, q$の0x100の各次数の係数を同様に下の桁から確定させることが出来るので最終的に $pq=n$ となるまで探索して後は復号するだけ。

### code

```python
from xcrypto import dec_pq, num_to_str
from xlog import XLog


logger = XLog()


def get_pq(p, q):
    str_p = ""
    str_q = ""
    for p_i in reversed(p):
        str_p += "3"
        str_p += str(p_i)
    for q_j in reversed(q):
        str_q += "3"
        str_q += str(q_j)

    return int(str_p, 16), int(str_q, 16)


if __name__ == '__main__':
    N = 13234306273608973531555502334446720401597326792644624514228362685813698571322410829494757436628326246629203126562441757712029708148508660279739210512110734001019285095467352938553972438629039005820507697493315650840705745518918873979766056584458077636454673830866061550714002346318865318536544606580475852690351622415519854730947773248376978689711597597169469401661488756669849772658771813742926651925442468141895198767553183304485662688033274567173210826233405235701905642383704395846192587563843422713499468379304400363773291993404144432403315463931374682824546730098380872658106314368520370995385913965019067624762624652495458399359096083188938802975032297056646831904294336374652136926975731836556951432035301855715375295216481079863945383657
    c = 9094564357254217771457579638296343398667095069849711922513911147179424647045593821415928967849073271368133854458732106409023539482401316282328817488781771665657515880026432487444729168909088425021111879152492812216384426360971681055941907554538267523250780508925995498013624610554177330113234686073838491261974164065812534037687990653834520243512128393881497418722817552604416319729143988970277812550536939775865310487081108925130229024749287074763499871216498398695877450736179371920963283041212502898938555288461797406895266037211533065670904218278235604002573401193114111627382958428536968266964975362791704067660270952933411608299947663325963289383426020609754934510085150774508301734516652467839087341415815719569669955613063226205647580528
    p = []
    q = []

    start_ij = 0

    while True:
        found = False
        target = N % (0x100)**(start_ij + 1)

        unknown_p_i, unknown_q_j = start_ij, start_ij

        p.append(-1)
        q.append(-1)

        for p_unknown in range(10):
            p[unknown_p_i] = p_unknown
            for q_unknown in range(10):
                q[unknown_q_j] = q_unknown
                _p, _q = get_pq(p, q)
                if _p*_q == N:
                    logger.info(f"found")
                    m = dec_pq(c, _p, _q, 0x10001)
                    logger.info(num_to_str(m))
                    exit()
                res = _p*_q

                if target == res % (0x100)**(start_ij + 1):
                    found = True
                    break

            if found:
                break

        start_ij += 1
```

### flag

`SECCON{I_would_always_love_the_cryptography_and_I_know_RSA_never_gets_old_So_Im_always_a_fan_of_this_mathematical_magic_and...Wait_This_flag_can_be_longer_than_I_expected_What_happened?}`

長すぎて見切れてる...

## fixer

### 略解

pycが配られる。uncompileはpython3.9に対応していない上にバージョンのマジックナンバーを偽装しても動かなかったのでdisで頑張ってデコンパイルする(時間はかかるものの予想より難しくはなかった)。問題はデコンパイル結果がlambdaの嵐だったので適度に分解したり定義された関数に直していく。頑張って読むと"入力文字列を各文字に対応した数字を要素とする配列に変換し、それを引数としてある関数が生成され、それに0を与えた結果を出力する"だったので、計算中のダンプ出来る数字を適当にダンプして動作をGuessした。

### 問題概要

pycファイルをくれる。但しバージョンは出たばかりの3.9である。このせいか既存のpycのデコンパイルツールは上手く動いてくれなかった。

動作としてはまず入力が`"^SECCON{([A-Z]+)}$"`にマッチするかを調べ、もしマッチするならコード中で定義されている無名関数の引数として括弧内を渡す。その結果が正ならその入力がフラグとなる。

### デコンパイル

Pythonの標準ライブラリにあるdisモジュールを使うとpycをディスアセンブル出来るのでこれを使う。pycの内部構造は良く知らないが[ここのリンク](https://stackoverflow.com/questions/32562163/how-can-i-understand-a-pyc-file-content)に載っているコードを利用したら良い感じにディスアセンブル出来た(結果はクソ長いので割愛)。

ディスアセンブル結果が得られたのでこれを人力デコンパイルする。特にネックとなるのは無名関数のために用意されているコードオブジェクトの部分でlambdaが連発されているせいで読みにくい。ひとまず上の方にあるコードオブジェクトから解析をしていく。

一番初めに遭遇するコードオブジェクトはこちらでこいつの引数にフラグの括弧内が渡される。

```
Disassembly of <code object <lambda> at 0x7f0185bdf870, file "fixer.py", line 9>:
  9           0 LOAD_CONST               1 (<code object <lambda> at 0x7f0185bcb5b0, file "fixer.py", line 9>)
              2 LOAD_CONST               2 ('<lambda>.<locals>.<lambda>')
              4 MAKE_FUNCTION            0
              6 LOAD_CONST               3 (13611142019359843741091679554812914051545792465993098606064046040462991)
              8 CALL_FUNCTION            1
             10 LOAD_CONST               4 (<code object <lambda> at 0x7f0185bcb7c0, file "fixer.py", line 9>)
             12 LOAD_CONST               2 ('<lambda>.<locals>.<lambda>')
             14 MAKE_FUNCTION            0
             16 LOAD_CONST               5 (<code object <lambda> at 0x7f0185bcba80, file "fixer.py", line 9>)
             18 LOAD_CONST               2 ('<lambda>.<locals>.<lambda>')
             20 MAKE_FUNCTION            0
             22 CALL_FUNCTION            1
             24 LOAD_CONST               6 (<code object <lambda> at 0x7f0185bcbf50, file "fixer.py", line 9>)
             26 LOAD_CONST               2 ('<lambda>.<locals>.<lambda>')
             28 MAKE_FUNCTION            0
             30 CALL_FUNCTION            1
             32 LOAD_CONST               4 (<code object <lambda> at 0x7f0185bcb7c0, file "fixer.py", line 9>)
             34 LOAD_CONST               2 ('<lambda>.<locals>.<lambda>')
             36 MAKE_FUNCTION            0
             38 LOAD_CONST               7 (<code object <lambda> at 0x7f0185bdc2f0, file "fixer.py", line 9>)
             40 LOAD_CONST               2 ('<lambda>.<locals>.<lambda>')
             42 MAKE_FUNCTION            0
             44 CALL_FUNCTION            1
             46 LOAD_CONST               4 (<code object <lambda> at 0x7f0185bcb7c0, file "fixer.py", line 9>)
             48 LOAD_CONST               2 ('<lambda>.<locals>.<lambda>')
             50 MAKE_FUNCTION            0
             52 LOAD_CONST               8 (<code object <lambda> at 0x7f0185bd8870, file "fixer.py", line 9>)
             54 LOAD_CONST               2 ('<lambda>.<locals>.<lambda>')
             56 MAKE_FUNCTION            0
             58 CALL_FUNCTION            1
             60 CALL_FUNCTION            1
             62 LOAD_FAST                0 (s)
             64 CALL_FUNCTION            1
             66 CALL_FUNCTION            1
             68 LOAD_CONST               9 (0)
             70 CALL_FUNCTION            1
             72 CALL_FUNCTION            1
             74 RETURN_VALUE
```

各命令の概要はだいたい次の通り

- `LOAD_HOGE`: スタックに積む
- `CALL_FUNCTION <n>`: `<n>`だけpopして引数とし、その下にある関数をpopしてcallする。結果はpushされる。
- `MAKE_FUNCTION`: スタックからコードオブジェクトと名前をpopして関数を生成し、スタックに積む(よくわからんけど今回は`lambda`を使った無名関数の作成に使われている)

関数呼び出しに関してはx86(32bit)に似ている。手元のメモを参照するとだいたい次のようなスタックの動きをしていたらしい。

```
58実行後(ip=60)

(f: 0x7f0185bcb7c0)(f: 0x7f0185bd8870)
(f: 0x7f0185bcb7c0)(f: 0x7f0185bdc2f0)
(f: 0x7f0185bcb7c0)(f: 0x7f0185bcba80)(f: 0x7f0185bcbf50)
(f: 0x7f0185bcb5b0)(13611142019359843741091679554812914051545792465993098606064046040462991)

62実行後(ip=64)

s
((f: 0x7f0185bcb7c0)(f: 0x7f0185bdc2f0))((f: 0x7f0185bcb7c0)(f: 0x7f0185bd8870))
(f: 0x7f0185bcb7c0)(f: 0x7f0185bcba80)(f: 0x7f0185bcbf50)
(f: 0x7f0185bcb5b0)(13611142019359843741091679554812914051545792465993098606064046040462991)

64実行後(ip=66)

((f: 0x7f0185bcb7c0)(f: 0x7f0185bdc2f0))((f: 0x7f0185bcb7c0)(f: 0x7f0185bd8870))(s)
(f: 0x7f0185bcb7c0)(f: 0x7f0185bcba80)(f: 0x7f0185bcbf50)
(f: 0x7f0185bcb5b0)(13611142019359843741091679554812914051545792465993098606064046040462991)

68実行後(ip=70)

0
((f: 0x7f0185bcb7c0)(f: 0x7f0185bcba80)(f: 0x7f0185bcbf50))(((f: 0x7f0185bcb7c0)(f: 0x7f0185bdc2f0))((f: 0x7f0185bcb7c0)(f: 0x7f0185bd8870))(s))
(f: 0x7f0185bcb5b0)(13611142019359843741091679554812914051545792465993098606064046040462991)

70実行後(ip=72)

((f: 0x7f0185bcb7c0)(f: 0x7f0185bcba80)(f: 0x7f0185bcbf50))(((f: 0x7f0185bcb7c0)(f: 0x7f0185bdc2f0))((f: 0x7f0185bcb7c0)(f: 0x7f0185bd8870))(s))(0)
(f: 0x7f0185bcb5b0)(13611142019359843741091679554812914051545792465993098606064046040462991)

72実行後(ip=74)

(f: 0x7f0185bcb5b0)(13611142019359843741091679554812914051545792465993098606064046040462991)(((f: 0x7f0185bcb7c0)(f: 0x7f0185bcba80)(f: 0x7f0185bcbf50))(((f: 0x7f0185bcb7c0)(f: 0x7f0185bdc2f0))((f: 0x7f0185bcb7c0)(f: 0x7f0185bd8870))(s))(0))
```

この中で1番わかりやすいのは0x7f0185bcb5b0に配置されているコードオブジェクトである。

```
Disassembly of <code object <lambda> at 0x7f0185bcb5b0, file "fixer.py", line 9>:
  9           0 LOAD_CLOSURE             0 (a)
              2 BUILD_TUPLE              1
              4 LOAD_CONST               1 (<code object <lambda> at 0x7f0185bc4450, file "fixer.py", line 9>)
              6 LOAD_CONST               2 ('<lambda>.<locals>.<lambda>.<locals>.<lambda>')
              8 MAKE_FUNCTION            8 (closure)
             10 RETURN_VALUE

Disassembly of <code object <lambda> at 0x7f0185bc4450, file "fixer.py", line 9>:
  9           0 LOAD_DEREF               0 (a)
              2 LOAD_FAST                0 (b)
              4 COMPARE_OP               2 (==)
              6 RETURN_VALUE
```

これは引数として受け取った`a`と等しいかを判定する"関数"を返す関数である。コード片にすると`lambda a: (lambda b: a == b)`のようになる。これに`13611142019359843741091679554812914051545792465993098606064046040462991`を渡しているため、72行目実行後のスタックに残っている値は`(((f: 0x7f0185bcb7c0)(f: 0x7f0185bcba80)(f: 0x7f0185bcbf50))(((f: 0x7f0185bcb7c0)(f: 0x7f0185bdc2f0))((f: 0x7f0185bcb7c0)(f: 0x7f0185bd8870))(s))(0)) == 13611142019359843741091679554812914051545792465993098606064046040462991`になる。

もうこの時点で頭が痛い(プレビューが読みづらくて地獄になってる)が、まだまだ無名関数は残っている。Writeup的に運が良いのは残りの無名関数は適当に読んでいくだけで同じディスアセンブル結果を得られるコードを得られるぐらいには単純である、というわけで割愛する。

問題は実際出来上がったデコンパイル結果が目を反らしたくなるぐらいlambda塗れだったということである。実際に出来上がった地獄のデコンパイル結果がこちら

```python
import re

s = input()
m = re.match('^SECCON{([A-Z]+)}$', s)

if not m:
    print("invalid flag")
else:
    s = m.group(1)
    f = lambda s: ((lambda a: (lambda b: a == b))(13611142019359843741091679554812914051545792465993098606064046040462991))(((((lambda a: (lambda b: a(lambda c: b(b)(c)))(lambda b: a(lambda c: b(b)(c))))(lambda f: (lambda b: (lambda c: (lambda d: d if len(c) == 0 else b(f(b)(c[1:])(d))(c[0]))))))(lambda a: (lambda b: a * (lambda a: (lambda b: a(lambda c: b(b)(c)))(lambda b: a(lambda c: b(b)(c))))(lambda a: (lambda b: b - 10 if b > 266 else a(a(b+11))))(b) + b)))((((lambda a: (lambda b: a(lambda c: b(b)(c)))(lambda b: a(lambda c: b(b)(c))))(lambda f: (lambda b: (lambda c: [] if len(c) == 0 else [b(ord(c[0]) - 65)] + f(b)(c[1:])))))((lambda a: (lambda b: a(lambda c: b(b)(c)))(lambda b: a(lambda c: b(b)(c))))(lambda a: (lambda b: 1 if b == 0 else (b+1)*a(b-1) + 7 & 255))))(s)))(0))

    if f(s):
        print("correct")
    else:
        print("wrong")

    # # 0x7f0185bcb7c0
    # g = lambda a: (lambda b: a(lambda c: b(b)(c)))(lambda b: a(lambda c: b(b)(c)))

    # # 0x7f0185bcba80
    # h = lambda f: (lambda b: (lambda c: (lambda d: d if len(c) == 0 else b(f(b)(c[1:])(d))(c[0]))))

    # # 0x7f0185bcbf50
    # i = lambda a: (lambda b: a * (lambda a: (lambda b: a(lambda c: b(b)(c)))(lambda b: a(lambda c: b(b)(c))))(lambda a: (lambda b: b - 10 if b > 266 else a(a(b+11))))(b) + b)

    # 0x7f0185bdc2f0
    # j = lambda f: (lambda b: (lambda c: [] if len(c) == 0 else [b(ord(c[0]) - 65)] + f(b)(c[1:])))

    # 0x7f0185bd8870
    # k = lambda a: (lambda b: 1 if b == 0 else (b+1)*a(b-1) + 7 & 255)

```

無名関数の部分が見切れているが見ないほうが良いぐらいにはアホみたいに長い。コメントアウトして無名関数を分割してコードオブジェクト毎に書いておいたが、これを見て察して欲しい。

このままではどうあがいても解けないので無名関数に適当に名前を付けたりしていく。ついでに解析をすると`(((f: 0x7f0185bcb7c0)(f: 0x7f0185bdc2f0))((f: 0x7f0185bcb7c0)(f: 0x7f0185bd8870))(s))`の部分で配列を返していることが分かった。これを次のコードで入力毎に出力してみる。

```python
import re

target = 13611142019359843741091679554812914051545792465993098606064046040462991

# 0x7f0185bcb7c0
def g(a):
    g_in = lambda b: a(lambda c: (b(b))(c))

    return g_in(g_in)


# 0x7f0185bcba80
def h(f):
    return lambda b: (lambda c: (lambda d: d if len(c) == 0 else b(f(b)(c[1:])(d))(c[0])))


# 0x7f0185bcbf50
def i(a):
    # print(hex(a))
    return lambda b: a * g(lambda a: (lambda b: b - 10 if b > 266 else a(a(b+11))))(b) + b


# 0x7f0185bdc2f0
def j(f):
    return (lambda b: (lambda c: [] if len(c) == 0 else [b(ord(c[0]) - 65)] + f(b)(c[1:])))


# 0x7f0185bd8870
def k(a):
    def k_in(b):
        return 1 if b == 0 else ((b+1) * a(b-1) + 7) & 255
    return k_in


# 引数(uppercaseからなる文字列)を文字にバラして文字に対し一意な数に変換した配列を返す
def to_arr(s):
    f_j = g(j)
    f_k = g(k)
    f_gjk = f_j(f_k)
    f0 = f_gjk

    return f0(s)


def arr_to_func(arr):
    g_h = g(h)
    g_h_i = g_h(i)
    return g_h_i(arr)


# s = input()
test_data = ["AAA", "BBBBBB", "ABC", "ABCD", "XDJFLKEMDJFA", "AAAAAAAAA", "YJSNPIMURKMR", "OAAAA", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"]
for test_text in test_data:
    s = f"SECCON{{{test_text}}}"
    m = re.match('^SECCON{([A-Z]+)}$', s)

    if not m:
        print("invalid flag")
    else:
        s = m.group(1)

        arr = to_arr(s)
        f0 = arr_to_func(arr)
        res = f0(0)

    print(f"{s}: {list(map(hex, arr))}")

    # if f(s):
    #     print("correct")
    # else:
    #     print("wrong")

```

結果は次の通り

```
AAA: ['0x1', '0x1', '0x1']
BBBBBB: ['0x9', '0x9', '0x9', '0x9', '0x9', '0x9']
ABC: ['0x1', '0x9', '0x22']
ABCD: ['0x1', '0x9', '0x22', '0x8f']
XDJFLKEMDJFA: ['0x27', '0x8f', '0x83', '0xf3', '0xe7', '0xa8', '0xd2', '0xc2', '0x8f', '0x83', '0xf3', '0x1']
AAAAAAAAA: ['0x1', '0x1', '0x1', '0x1', '0x1', '0x1', '0x1', '0x1', '0x1']
YJSNPIMURKMR: ['0xd6', '0x83', '0x60', '0xa3', '0x47', '0xa6', '0xc2', '0x1a', '0x63', '0xa8', '0xc2', '0x63']
OAAAA: ['0x94', '0x1', '0x1', '0x1', '0x1']
ABCDEFGHIJKLMNOPQRSTUVWXYZ: ['0x1', '0x9', '0x22', '0x8f', '0xd2', '0xf3', '0xac', '0x67', '0xa6', '0x83', '0xa8', '0xe7', '0xc2', '0xa3', '0x94', '0x47', '0xbe', '0x63', '0x60', '0x87', '0x1a', '0x43', '0xc', '0x27', '0xd6', '0xc3']
```

これを見ると入力の各文字に対し一意な数字が振られてそれを並べた配列になっている。よって、この生成手順はよくわからないが、入力に対してこの配列が何になるかは事前に計算しておくことが出来る。

続いてこの配列を引数として`((f: 0x7f0185bcb7c0)(f: 0x7f0185bcba80)(f: 0x7f0185bcbf50))`に渡しているがこれは関数を生成する。そしてそこに`0`を渡すと数値を返す(たぶん)。

ここで先程のコードの`i`関数に注目するとここの引数`a`はおそらく数値である。というわけでこいつをdumpしてみる(上のコードのコメントを外す)、長いので一番下の`"ABCDEFG..."`だけの結果は次の通り。

```
0x0
0xc3
0xc499
0xc55dc0
0xc6231dcc
0xc6e940ea0f
0xc7b02a2af929
0xc877da552422b0
0xc940522f7946d310
0xca099281a8c019e373
0xcad39c142a68d9fd5731
0xcb9e6fb03e9342d7548878
0xcc6a0e1feed1d61a2bdd010c
0xcd36782e0ec0a7f04608de0daf
0xce03aea63ccf6898364ee6ebbd71
0xced1b254e30c3800ce8535d2a92f58
0xcfa0840737ef4438cf53bb087bd88800
0xd070248b3f27337d08230ec38454608883
0xd14094afca665ab0852b31d247d8b4e90c29
0xd211d5447a30c10b35b05d041a208d9df53590
0xd2e3e719beaaf1cc40e60d611e3aae2b932ac63c
0xd3b6cb00d8699cbe0d26f36e7f58e8d9bebdf1032f
0xd48a81cbd942065acb341a61edd841c2987caef43301
0xd55f0c4da51b486125ff4e7c4fc61a045b152ba3273490
0xd6346b59f2c063a987254dcacc15e01e5f7040ceca5bc4b2
0xd70a9fc54cb3240d30ac731896e1f5fe7dcfb10f99262076bb
ABCDEFGHIJKLMNOPQRSTUVWXYZ: ['0x1', '0x9', '0x22', '0x8f', '0xd2', '0xf3', '0xac', '0x67', '0xa6', '0x83', '0xa8', '0xe7', '0xc2', '0xa3', '0x94', '0x47', '0xbe', '0x63', '0x60', '0x87', '0x1a', '0x43', '0xc', '0x27', '0xd6', '0xc3']
```

この結果と配列をにらめっこして、どうやら`i > 0`において`n[i] = n[i-1] * 0x100 + n[i-1] + arr[-i]`のような関係があるとGuessした。但し`n[i]`は`i`番目に出力された数で`arr[i]`は生成された数列の`i`番目の要素である。

ということはこれを逆に辿れば`arr[i]`を順に求める事ができそうである。やり方としては`n[i-1] * 0x100 + n[i-1]`が`n[i-1] * (0x101)`なので`n[i]`から`arr[i]`を総当りして引いていき、その結果が0x101の倍数であれば確定とする。

得られた結果を与えられたpycに食わせたら`correct`と出たのでこれがフラグである。

### code

```python
from string import ascii_uppercase
import re

# 0x7f0185bcb7c0
def g(a):
    g_in = lambda b: a(lambda c: (b(b))(c))

    return g_in(g_in)


# 0x7f0185bcba80
def h(f):
    return lambda b: (lambda c: (lambda d: d if len(c) == 0 else b(f(b)(c[1:])(d))(c[0])))


# 0x7f0185bcbf50
def i(a):
    print(hex(a))
    return lambda b: a * g(lambda a: (lambda b: b - 10 if b > 266 else a(a(b+11))))(b) + b


# 0x7f0185bdc2f0
def j(f):
    return (lambda b: (lambda c: [] if len(c) == 0 else [b(ord(c[0]) - 65)] + f(b)(c[1:])))


# 0x7f0185bd8870
def k(a):
    def k_in(b):
        return 1 if b == 0 else ((b+1) * a(b-1) + 7) & 255
    return k_in


# 引数(uppercaseからなる文字列)を文字にバラして文字に対し一意な数に変換した配列を返す
def to_arr(s):
    f_j = g(j)
    f_k = g(k)
    f_gjk = f_j(f_k)
    f0 = f_gjk

    return f0(s)


def arr_to_func(arr):
    g_h = g(h)
    g_h_i = g_h(i)
    return g_h_i(arr)


def exploit():
    arr = to_arr(ascii_uppercase)
    n_dict = {c:n for c, n in zip(ascii_uppercase, arr)}

    flag = ""
    target = 13611142019359843741091679554812914051545792465993098606064046040462991

    while target > 0:
        for c, n in n_dict.items():
            if (target - n) % 0x101 == 0:
                print(c)
                flag += c
                target = (target - n) // 0x101
                break

    print(flag)


exploit()
```

### flag

`SECCON{MYCJILJCZEKRDNNWZUGSEZQSKKPKZA}`
