+++
title = "Writeup: AlpacaHack Round 4 - pytecode"
date = 2024-10-06

[taxonomies]
tags = ["CTF", "Writeup", "Rev", "Pickle", "Python", "Python_Bytecode"]
+++

## TL;DR

- PickleバイトコードでPythonのコードオブジェクトを構築しながらフラグをチェックする
	- co_argcountとco_codestring以外は固定でこれらをSETITEMSオペコードを実行してセットしたものをNEWOBJオペコードでインスタンス化している
- 構築されるコードオブジェクトにもいくらかの難読化が施されている
	- co_consts や co_names が空: 定数等が変数として使えないため、引数の数値同士を除算、減算する形で1や0を作ってそこを起点に他の数値も強引に作っている
	- co_varnamesが全てクエスチョン (`"?"`) になっている
- 構築されるコードオブジェクトとその引数を取得して動作を逆アセンブラと気合で解析し、フラグを逆算する
	- (突然の宣伝) 筆者は既に[Pickle動的解析用のフレームワーク](https://github.com/Xornet-Euphoria/pickaxe/blob/main/pickaxe/unpickler.py)を書いているのでそれで命令をフックして取得した

<!-- more -->

## Prerequisite

- Pickle
- Pythonのバイトコード
	- コードオブジェクトについて
	- ディスアセンブルの方法: `dis`モジュールの`dis`関数等

## Writeup

配布ソースコードは次の通り

```python
import sys
import pickle


# check your python version
if (v := sys.version_info) and v.major == 3 and v.minor == 11:
    print("[+] version check: ok")
else:
    print("[+] Requirement: Python 3.11")
    print("    Please change the version of Python")
    print("    Or use the Dockerfile in distfiles")
    exit()

# get input and sanity check
inp = input("flag> ").encode("ascii")
if len(inp) != 64:
    print("[!] check the length of flag")
    exit(1)

for c in inp:
    if c > 0x7f:
        print("[!] ASCII printable only")
        exit(1)

# rev time
hex_code = "8c0574797065738c0c46756e6374696f6e547970659372390500008c0574797065738c08436f64655479706593723a05000028284b024b00324d3905324b0043e697007c007c006b03000000007d027c007c02190000000000000000007d037c037c037a0a00007d047c047c047a0800007d057c057c057a0300007d067c057c067a0300007d077c077c057a0300007d087c077c057a0a00007d097c087c097a0a00007d0a7c087c067a0a00007d0b7c087c057a0a00007d0c7c047c057c067c097c077c0a7c0b7c0c67087d0d7c0467017c087a0500007d0e7c0d44005d227d0f7c0f7c087a0500007d107c107c087a0000007d1102007c017c007c107c11850219000000000000000000a6010000ab0100000000000000007c0e7c0f3c0000008c237c0e53002932288c086275696c74696e738c0767657461747472938c013f8c075f5f6d756c5f5f86524d39058552696275696c74696e730a7475706c650a8c037468658c0463616b658c0269734d390543016143036c69656c72a31c0000696275696c74696e730a7475706c650a817d86818c085f5f6d61696e5f5f8c03696e70938c086275696c74696e738c0767657461747472938c086275696c74696e738c03696e74938c0a66726f6d5f62797465738652865272193400003067313333370a67313333380a2867373333310a284b004b034b06432697007c007c0178027802190000000000000000007c027a190000630363023c0000007c00530075696275696c74696e730a7475706c650a817d86816731333333370a4b008a083713dec0adde371387523067313333370a67313333380a2867373333310a284b004b034b06433497007c007c02190000000000000000007c007c011900000000000000000063027c007c013c0000007c007c023c0000007c00530075696275696c74696e730a7475706c650a817d86816731333333370a4b024b0787523067313333370a67313333380a2867373333310a284b004b034b06434697007c007c01190000000000000000007d037c037c027a0a00007d047c047c047a0a00007d057c047c056b000000000072037c040b006e017c047c007c013c0000007c00530075696275696c74696e730a7475706c650a817d86816731333333370a4b048a0980808080808080800087523067313333370a67313333380a2867373333310a284b004b034b06438c97007c007c01190000000000000000007d037c037c037a0200007d047c047c027a0300007c047a0a00007d057c037c057a0100007d067c037c027a1600007d037c047c047a0000007d077c077c077a0500007c077a0000007d087c047c087a0300007d097c097c027a0a00007d0a7c037c067c0a7a0300007a1400007d037c037c007c013c0000007c00530075696275696c74696e730a7475706c650a817d86816731333333370a4b014b0d87523067313333370a67313333380a2867373333310a284b004b044b06432e97007c007c01190000000000000000007c007c02190000000000000000007a0c00007c007c033c0000007c00530075696275696c74696e730a7475706c650a817d8681286731333333370a4b014b064b0174523067313333370a67313333380a2867373333310a284b004b034b06433497007c007c01190000000000000000007c007c01190000000000000000007c027a0900007a0c00007c007c013c0000007c00530075696275696c74696e730a7475706c650a817d86816731333333370a4b054b0c87523067313333370a67313333380a2867373333310a284b004b034b06433497007c007c02190000000000000000007c007c011900000000000000000063027c007c013c0000007c007c023c0000007c00530075696275696c74696e730a7475706c650a817d86816731333333370a4b034b0687523067313333370a67313333380a2867373333310a284b004b024b0643f097007c007c007a0600007d027c007c007a0200007d037c037c037a0000007d047c037c047a0000007d057c047c047a0800007d067c047c057a0000007d077c057c047a0500007d087c067c047a0500007c037a0a00007d097c037c087a0300007d0a7c0a7c047a0500007d0b7c037c0a7a0300007c037a0a00007d0c7c097c087a0500007d0d7c097c0b7c0a7a0000007c037a0a00007a0500007d0e7c027c037c047c057c067c077c087c0967087d0f7c0f44005d1b7d107c017c10190000000000000000007c007a0c00007c017c103c0000007c0d7c007a0500007c0e7a0000007c0c7a0100007d008c1c7c01530075696275696c74696e730a7475706c650a817d86818a0831733173371337136731333333370a86523067313333370a67313333380a2867373333310a284b004b024b06430e97007c007c016b0200000000530075696275696c74696e730a7475706c650a817d86816731333333370a288a08681b8ed0fbbd6c418a0941c7497ece39ad89008a084aeddba97935e5158a095ea56bfce5024e9f008a0894076c3bc5a9d72b8a08376e39db1e2c8a6d8a0982c47dc69701a288008a080a5558e826cbfd656c86522e"
if pickle.loads(bytes.fromhex(hex_code)):
    print("Congrats!! Submit your flag.")
else:
    print("nope")
```

Pythonバージョンと文字数のチェックを突破すると、Pickleのバイトコードをloadしていることから内部でREDUCEやらで関数を実行していると推定できる。

いつものように[pickletools.py](https://github.com/python/cpython/blob/main/Lib/pickletools.py)を使うとクソ長い結果が得られるが気合で読む[^1]。先頭の方を見ると次のようになっている。

```
    0: \x8c SHORT_BINUNICODE 'types'
    7: \x8c SHORT_BINUNICODE 'FunctionType'
   21: \x93 STACK_GLOBAL
   22: r    LONG_BINPUT 1337
   27: \x8c SHORT_BINUNICODE 'types'
   34: \x8c SHORT_BINUNICODE 'CodeType'
   44: \x93 STACK_GLOBAL
   45: r    LONG_BINPUT 1338
   50: (    MARK
   51: (        MARK
   52: K            BININT1    2
   54: K            BININT1    0
   56: 2            DUP
   57: M            BININT2    1337
   60: 2            DUP
   61: K            BININT1    0
   63: C            SHORT_BINBYTES b'\x97\x00|\x00|\x00k\x03\x00\x00\x00\x00}\x02|\x00|\x02\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00}\x03|\x03|\x03z\n\x00\x00}\x04|\x04|\x04z\x08\x00\x00}\x05|\x05|\x05z\x03\x00\x00}\x06|\x05|\x06z\x03\x00\x00}\x07|\x07|\x05z\x03\x00\x00}\x08|\x07|\x05z\n\x00\x00}\t|\x08|\tz\n\x00\x00}\n|\x08|\x06z\n\x00\x00}\x0b|\x08|\x05z\n\x00\x00}\x0c|\x04|\x05|\x06|\t|\x07|\n|\x0b|\x0cg\x08}\r|\x04g\x01|\x08z\x05\x00\x00}\x0e|\rD\x00]"}\x0f|\x0f|\x08z\x05\x00\x00}\x10|\x10|\x08z\x00\x00\x00}\x11\x02\x00|\x01|\x00|\x10|\x11\x85\x02\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00|\x0e|\x0f<\x00\x00\x00\x8c#|\x0eS\x00'
  295: )            EMPTY_TUPLE
  296: 2            DUP
  297: (            MARK
  298: \x8c             SHORT_BINUNICODE 'builtins'
  308: \x8c             SHORT_BINUNICODE 'getattr'
  317: \x93             STACK_GLOBAL
  318: \x8c             SHORT_BINUNICODE '?'
  321: \x8c             SHORT_BINUNICODE '__mul__'
  330: \x86             TUPLE2
  331: R                REDUCE
  332: M                BININT2    1337
  335: \x85             TUPLE1
  336: R                REDUCE
  337: i                INST       'builtins tuple' (MARK at 297)
  353: \x8c         SHORT_BINUNICODE 'the'
  358: \x8c         SHORT_BINUNICODE 'cake'
  364: \x8c         SHORT_BINUNICODE 'is'
  368: M            BININT2    1337
  371: C            SHORT_BINBYTES b'a'
  374: C            SHORT_BINBYTES b'lie'
  379: l            LIST       (MARK at 51)
  380: r        LONG_BINPUT 7331
  385: i        INST       'builtins tuple' (MARK at 50)
  401: \x81 NEWOBJ
  402: }    EMPTY_DICT
  403: \x86 TUPLE2
  404: \x81 NEWOBJ
```

Pythonのコードオブジェクトを`types.CodeType`のインスタンスを作る形で構築して、`types.FunctionType`に渡して関数を生成している事がわかる。`dis.dis`を使うとこの関数を逆アセンブル出来るので確認すると次のようになっている。なお、そのままだと`co_varnames`が`("X" for _ in range(1337))`で非常に読みづらいため差し替えている。

```
1339           0 RESUME                   0
               2 LOAD_FAST                0 (var_0)
               4 LOAD_FAST                0 (var_0)
               6 COMPARE_OP               3 (!=)
              12 STORE_FAST               2 (var_2)
              14 LOAD_FAST                0 (var_0)
              16 LOAD_FAST                2 (var_2)
              18 BINARY_SUBSCR
              28 STORE_FAST               3 (var_3)
              30 LOAD_FAST                3 (var_3)
              32 LOAD_FAST                3 (var_3)
              34 BINARY_OP               10 (-)
              38 STORE_FAST               4 (var_4)
              40 LOAD_FAST                4 (var_4)
              42 LOAD_FAST                4 (var_4)
              44 BINARY_OP                8 (**)
              48 STORE_FAST               5 (var_5)
              50 LOAD_FAST                5 (var_5)
              52 LOAD_FAST                5 (var_5)
              54 BINARY_OP                3 (<<)
              58 STORE_FAST               6 (var_6)
              60 LOAD_FAST                5 (var_5)
              62 LOAD_FAST                6 (var_6)
              64 BINARY_OP                3 (<<)
              68 STORE_FAST               7 (var_7)
              70 LOAD_FAST                7 (var_7)
              72 LOAD_FAST                5 (var_5)
              74 BINARY_OP                3 (<<)
              78 STORE_FAST               8 (var_8)
              80 LOAD_FAST                7 (var_7)
              82 LOAD_FAST                5 (var_5)
              84 BINARY_OP               10 (-)
              88 STORE_FAST               9 (var_9)
              90 LOAD_FAST                8 (var_8)
              92 LOAD_FAST                9 (var_9)
              94 BINARY_OP               10 (-)
              98 STORE_FAST              10 (var_10)
             100 LOAD_FAST                8 (var_8)
             102 LOAD_FAST                6 (var_6)
             104 BINARY_OP               10 (-)
             108 STORE_FAST              11 (var_11)
             110 LOAD_FAST                8 (var_8)
             112 LOAD_FAST                5 (var_5)
             114 BINARY_OP               10 (-)
             118 STORE_FAST              12 (var_12)
             120 LOAD_FAST                4 (var_4)
             122 LOAD_FAST                5 (var_5)
             124 LOAD_FAST                6 (var_6)
             126 LOAD_FAST                9 (var_9)
             128 LOAD_FAST                7 (var_7)
             130 LOAD_FAST               10 (var_10)
             132 LOAD_FAST               11 (var_11)
             134 LOAD_FAST               12 (var_12)
             136 BUILD_LIST               8
             138 STORE_FAST              13 (var_13)
             140 LOAD_FAST                4 (var_4)
             142 BUILD_LIST               1
             144 LOAD_FAST                8 (var_8)
             146 BINARY_OP                5 (*)
             150 STORE_FAST              14 (var_14)
             152 LOAD_FAST               13 (var_13)
             154 GET_ITER
         >>  156 FOR_ITER                34 (to 226)
             158 STORE_FAST              15 (var_15)
             160 LOAD_FAST               15 (var_15)
             162 LOAD_FAST                8 (var_8)
             164 BINARY_OP                5 (*)
             168 STORE_FAST              16 (var_16)
             170 LOAD_FAST               16 (var_16)
             172 LOAD_FAST                8 (var_8)
             174 BINARY_OP                0 (+)
             178 STORE_FAST              17 (var_17)
             180 PUSH_NULL
             182 LOAD_FAST                1 (var_1)
             184 LOAD_FAST                0 (var_0)
             186 LOAD_FAST               16 (var_16)
             188 LOAD_FAST               17 (var_17)
             190 BUILD_SLICE              2
             192 BINARY_SUBSCR
             202 PRECALL                  1
             206 CALL                     1
             216 LOAD_FAST               14 (var_14)
             218 LOAD_FAST               15 (var_15)
             220 STORE_SUBSCR
             224 JUMP_BACKWARD           35 (to 156)
         >>  226 LOAD_FAST               14 (var_14)
             228 RETURN_VALUE
```

序盤に長い処理があり、続いてループがあるという構造になっている。序盤の処理は`co_consts`が空のタプルであることから`LOAD_CONST`で取得できないため、intの引数を利用して気合で作っている。特に次のようにして0と1を作れば後は四則演算の組み合わせで幾らでも作ることが出来るため最序盤にこれを作るコードが存在している。

- 0: `x - x`, 後に `x % x` も登場
- 1: `x // x`

このコードを人力デコンパイルして動作を把握すると、だいたい次のような事をしている。

```python
def f(var_0, var_1):
	var_2 = var_0 != var_0  # always False
	var_3 = var_0[False]    # = var_0[0]
	var_4 = var_3 - var_3   # always 0
	var_5 = var_4 ** var_4  # always 0**0 (= 1 at python)
	var_6 = var_5 << var_5  # 1 << 1 = 2
	var_7 = var_5 << var_6  # 1 << 2 = 4
	var_8 = var_7 << var_5  # 4 << 1 = 8
	var_9 = var_7 - var_5   # 7 - 5 = 3
	var_10 = var_8 - var_9  # 8 - 3 = 5
	var_11 = var_8 - var_6  # 8 - 2 = 6
	var_12 = var_8 - var_5  # 8 - 1 = 7
	var_13 = [
	    var_4,
	    var_5,
	    var_6,
	    var_9,
	    var_7,
	    var_10,
	    var_11,
	    var_12]  # = [0, 1, 2, 3, 4, 5, 6, 7]
	var_14 = [var_4] * var_8  # [0, 0, 0, 0, 0, 0, 0, 0]

	for var_15 in var_13:
		var_16 = var_8 * var_15  # 8*var_15
		var_17 = var_16 + var_8  # 8*var_15+8
		var_14[var_15] = var_1(var_0[var_16:var_17])

	return var_14  # the element on TOS is returned
```

もう少しわかりやすくすると次のような単純な処理になる。

```python
def f(l, f):
	ret = []
	
	for i in range(8):
		j = 8*i
		k = j+8  # 8*(i+1)
		ret[i] = f(l[j:k])

	return ret
```

2つの引数をとって、8要素ずつ何らかの関数を通した値の配列を返している。

なお、[pycdc](https://github.com/zrax/pycdc/tree/master)のようなデコンパイラを使おうとしてもPython 3.11には対応していないため、未対応命令に到達するまで (`list(range(8))`に相当するものを作る) しかデコンパイルされない。今後同じようにして関数が作られていくが、幾つかの関数 (おそらく [Specializing Adaptive Interpreter](https://peps.python.org/pep-0659/) に関連する命令を含んでいるもの) に関しても同様のことが起こっている。

この関数に渡す引数が何かを確認すると次のようになっている。

```txt
  405: \x8c SHORT_BINUNICODE '__main__'
  415: \x8c SHORT_BINUNICODE 'inp'
  420: \x93 STACK_GLOBAL
  421: \x8c SHORT_BINUNICODE 'builtins'
  431: \x8c SHORT_BINUNICODE 'getattr'
  440: \x93 STACK_GLOBAL
  441: \x8c SHORT_BINUNICODE 'builtins'
  451: \x8c SHORT_BINUNICODE 'int'
  456: \x93 STACK_GLOBAL
  457: \x8c SHORT_BINUNICODE 'from_bytes'
  469: \x86 TUPLE2
  470: R    REDUCE
  471: \x86 TUPLE2
  472: R    REDUCE
```

`inp`はソースコード中にある`inp`であり、それと`int.from_bytes`を渡していることから入力を8バイトずつ区切って`int.from_bytes`でビッグエンディアンの数値に変換した配列としている。

これ以後は次のような処理が続く。

```txt
  479: g    GET        1337
  485: g    GET        1338
  491: (    MARK
  492: g        GET        7331
  498: (        MARK
  499: K            BININT1    0
  501: K            BININT1    3
  503: K            BININT1    6
  505: C            SHORT_BINBYTES b'\x97\x00|\x00|\x01x\x02x\x02\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00|\x02z\x19\x00\x00c\x03c\x02<\x00\x00\x00|\x00S\x00'
  545: u            SETITEMS   (MARK at 498)
  546: i        INST       'builtins tuple' (MARK at 491)
  562: \x81 NEWOBJ
  563: }    EMPTY_DICT
  564: \x86 TUPLE2
  565: \x81 NEWOBJ
```

メモからインデックス7331で引っ張ってきたリスト (↑でCodeオブジェクトを作る際に使ったもの) に対し数値とバイト列をそれぞれインデックス0, 6で代入している (SETITEMSオペコード)。これはそれぞれコードオブジェクトの`co_argcount`と `co_codestring`に対応することから、これらを変えながらコードオブジェクトと関数を構築し、引数を渡して実行しながらフラグをチェックしている。

ここまで分かればバイトコードと引数の数を抽出して同じように処理を把握するだけである。詳しくはCode節で掲載しているスクリプトに譲るが、intの配列に対してスワップやXOR、ビットローテート、減算の後に絶対値を取得、glibc heapに登場するsafe-linkingのようなビットシフトとXORといった処理が確認出来る。

最後にハードコードされたリストとこれらの処理が施されたリストを比較した結果を返し、これがTrueであればフラグとなる。

## Code

### Pythonバイトコードの逆アセンブル結果取得

- [pickaxe](https://github.com/Xornet-Euphoria/pickaxe/tree/main)が必要
	- 今回は最近作ったばかりの`pickaxe.CustomUnpickler`を使用
- 部分的なデコンパイル結果を得るために[pycdc](https://github.com/zrax/pycdc/tree/master)が必要

```python
from pickaxe import CustomUnpickler
import types

hex_code = "8c0574797065738c0c46756e6374696f6e547970659372390500008c0574797065738c08436f64655479706593723a05000028284b024b00324d3905324b0043e697007c007c006b03000000007d027c007c02190000000000000000007d037c037c037a0a00007d047c047c047a0800007d057c057c057a0300007d067c057c067a0300007d077c077c057a0300007d087c077c057a0a00007d097c087c097a0a00007d0a7c087c067a0a00007d0b7c087c057a0a00007d0c7c047c057c067c097c077c0a7c0b7c0c67087d0d7c0467017c087a0500007d0e7c0d44005d227d0f7c0f7c087a0500007d107c107c087a0000007d1102007c017c007c107c11850219000000000000000000a6010000ab0100000000000000007c0e7c0f3c0000008c237c0e53002932288c086275696c74696e738c0767657461747472938c013f8c075f5f6d756c5f5f86524d39058552696275696c74696e730a7475706c650a8c037468658c0463616b658c0269734d390543016143036c69656c72a31c0000696275696c74696e730a7475706c650a817d86818c085f5f6d61696e5f5f8c03696e70938c086275696c74696e738c0767657461747472938c086275696c74696e738c03696e74938c0a66726f6d5f62797465738652865272193400003067313333370a67313333380a2867373333310a284b004b034b06432697007c007c0178027802190000000000000000007c027a190000630363023c0000007c00530075696275696c74696e730a7475706c650a817d86816731333333370a4b008a083713dec0adde371387523067313333370a67313333380a2867373333310a284b004b034b06433497007c007c02190000000000000000007c007c011900000000000000000063027c007c013c0000007c007c023c0000007c00530075696275696c74696e730a7475706c650a817d86816731333333370a4b024b0787523067313333370a67313333380a2867373333310a284b004b034b06434697007c007c01190000000000000000007d037c037c027a0a00007d047c047c047a0a00007d057c047c056b000000000072037c040b006e017c047c007c013c0000007c00530075696275696c74696e730a7475706c650a817d86816731333333370a4b048a0980808080808080800087523067313333370a67313333380a2867373333310a284b004b034b06438c97007c007c01190000000000000000007d037c037c037a0200007d047c047c027a0300007c047a0a00007d057c037c057a0100007d067c037c027a1600007d037c047c047a0000007d077c077c077a0500007c077a0000007d087c047c087a0300007d097c097c027a0a00007d0a7c037c067c0a7a0300007a1400007d037c037c007c013c0000007c00530075696275696c74696e730a7475706c650a817d86816731333333370a4b014b0d87523067313333370a67313333380a2867373333310a284b004b044b06432e97007c007c01190000000000000000007c007c02190000000000000000007a0c00007c007c033c0000007c00530075696275696c74696e730a7475706c650a817d8681286731333333370a4b014b064b0174523067313333370a67313333380a2867373333310a284b004b034b06433497007c007c01190000000000000000007c007c01190000000000000000007c027a0900007a0c00007c007c013c0000007c00530075696275696c74696e730a7475706c650a817d86816731333333370a4b054b0c87523067313333370a67313333380a2867373333310a284b004b034b06433497007c007c02190000000000000000007c007c011900000000000000000063027c007c013c0000007c007c023c0000007c00530075696275696c74696e730a7475706c650a817d86816731333333370a4b034b0687523067313333370a67313333380a2867373333310a284b004b024b0643f097007c007c007a0600007d027c007c007a0200007d037c037c037a0000007d047c037c047a0000007d057c047c047a0800007d067c047c057a0000007d077c057c047a0500007d087c067c047a0500007c037a0a00007d097c037c087a0300007d0a7c0a7c047a0500007d0b7c037c0a7a0300007c037a0a00007d0c7c097c087a0500007d0d7c097c0b7c0a7a0000007c037a0a00007a0500007d0e7c027c037c047c057c067c077c087c0967087d0f7c0f44005d1b7d107c017c10190000000000000000007c007a0c00007c017c103c0000007c0d7c007a0500007c0e7a0000007c0c7a0100007d008c1c7c01530075696275696c74696e730a7475706c650a817d86818a0831733173371337136731333333370a86523067313333370a67313333380a2867373333310a284b004b024b06430e97007c007c016b0200000000530075696275696c74696e730a7475706c650a817d86816731333333370a288a08681b8ed0fbbd6c418a0941c7497ece39ad89008a084aeddba97935e5158a095ea56bfce5024e9f008a0894076c3bc5a9d72b8a08376e39db1e2c8a6d8a0982c47dc69701a288008a080a5558e826cbfd656c86522e"


functions = {}
prev_f_idx = -1

# extract functions
class PytecodeUnpickler(CustomUnpickler):
    def load_reduce(self):
	    # 厳密にはtypes.BuiltinFunctionTypeやtypes.BuiltinsMethodTypeの可能性があるが無視する (__code__が無くて飛ばすため)
        f: types.FunctionType = self.stack[-2]
        args = self.stack[-1]

        if hasattr(f, "__code__"):
            code = f.__code__
            if code.co_filename == "the":
                functions[self.ip] = (f, args)

        super().load_reduce()


	# change the `co_varnames` for readability
    def breakpoint_hook(self):
        if self.ip == 353:
            self.stack[-1] = tuple(f"var_{i}" for i in range(1337))

        return super().breakpoint_hook()


up = PytecodeUnpickler(bytes.fromhex(hex_code))
up.set_breakpoint(353)

inp = b"X" * 0x40

up.load()


import dis, marshal, subprocess
pycdc_path = "/path/to/pycdc"

for idx, (f, args) in functions.items():
    print(f"[+] Called at {idx}: f{args}")
    dis.dis(f)
    print("=" * 0x60)

    cd = marshal.dumps(f.__code__)
    marshaled_name = f"./marshaled/func_{idx}"
    with open(marshaled_name, "wb") as _f:
        _f.write(cd)

    decomp_f = open(marshaled_name+".py", "w")

    res = subprocess.run([pycdc_path, "-c", "-v", "3.11", marshaled_name], stdout=decomp_f)

    decomp_f.close()
```

### フラグの取得

```python
import pickletools, pickle

hex_code = "8c0574797065738c0c46756e6374696f6e547970659372390500008c0574797065738c08436f64655479706593723a05000028284b024b00324d3905324b0043e697007c007c006b03000000007d027c007c02190000000000000000007d037c037c037a0a00007d047c047c047a0800007d057c057c057a0300007d067c057c067a0300007d077c077c057a0300007d087c077c057a0a00007d097c087c097a0a00007d0a7c087c067a0a00007d0b7c087c057a0a00007d0c7c047c057c067c097c077c0a7c0b7c0c67087d0d7c0467017c087a0500007d0e7c0d44005d227d0f7c0f7c087a0500007d107c107c087a0000007d1102007c017c007c107c11850219000000000000000000a6010000ab0100000000000000007c0e7c0f3c0000008c237c0e53002932288c086275696c74696e738c0767657461747472938c013f8c075f5f6d756c5f5f86524d39058552696275696c74696e730a7475706c650a8c037468658c0463616b658c0269734d390543016143036c69656c72a31c0000696275696c74696e730a7475706c650a817d86818c085f5f6d61696e5f5f8c03696e70938c086275696c74696e738c0767657461747472938c086275696c74696e738c03696e74938c0a66726f6d5f62797465738652865272193400003067313333370a67313333380a2867373333310a284b004b034b06432697007c007c0178027802190000000000000000007c027a190000630363023c0000007c00530075696275696c74696e730a7475706c650a817d86816731333333370a4b008a083713dec0adde371387523067313333370a67313333380a2867373333310a284b004b034b06433497007c007c02190000000000000000007c007c011900000000000000000063027c007c013c0000007c007c023c0000007c00530075696275696c74696e730a7475706c650a817d86816731333333370a4b024b0787523067313333370a67313333380a2867373333310a284b004b034b06434697007c007c01190000000000000000007d037c037c027a0a00007d047c047c047a0a00007d057c047c056b000000000072037c040b006e017c047c007c013c0000007c00530075696275696c74696e730a7475706c650a817d86816731333333370a4b048a0980808080808080800087523067313333370a67313333380a2867373333310a284b004b034b06438c97007c007c01190000000000000000007d037c037c037a0200007d047c047c027a0300007c047a0a00007d057c037c057a0100007d067c037c027a1600007d037c047c047a0000007d077c077c077a0500007c077a0000007d087c047c087a0300007d097c097c027a0a00007d0a7c037c067c0a7a0300007a1400007d037c037c007c013c0000007c00530075696275696c74696e730a7475706c650a817d86816731333333370a4b014b0d87523067313333370a67313333380a2867373333310a284b004b044b06432e97007c007c01190000000000000000007c007c02190000000000000000007a0c00007c007c033c0000007c00530075696275696c74696e730a7475706c650a817d8681286731333333370a4b014b064b0174523067313333370a67313333380a2867373333310a284b004b034b06433497007c007c01190000000000000000007c007c01190000000000000000007c027a0900007a0c00007c007c013c0000007c00530075696275696c74696e730a7475706c650a817d86816731333333370a4b054b0c87523067313333370a67313333380a2867373333310a284b004b034b06433497007c007c02190000000000000000007c007c011900000000000000000063027c007c013c0000007c007c023c0000007c00530075696275696c74696e730a7475706c650a817d86816731333333370a4b034b0687523067313333370a67313333380a2867373333310a284b004b024b0643f097007c007c007a0600007d027c007c007a0200007d037c037c037a0000007d047c037c047a0000007d057c047c047a0800007d067c047c057a0000007d077c057c047a0500007d087c067c047a0500007c037a0a00007d097c037c087a0300007d0a7c0a7c047a0500007d0b7c037c0a7a0300007c037a0a00007d0c7c097c087a0500007d0d7c097c0b7c0a7a0000007c037a0a00007a0500007d0e7c027c037c047c057c067c077c087c0967087d0f7c0f44005d1b7d107c017c10190000000000000000007c007a0c00007c017c103c0000007c0d7c007a0500007c0e7a0000007c0c7a0100007d008c1c7c01530075696275696c74696e730a7475706c650a817d86818a0831733173371337136731333333370a86523067313333370a67313333380a2867373333310a284b004b024b06430e97007c007c016b0200000000530075696275696c74696e730a7475706c650a817d86816731333333370a288a08681b8ed0fbbd6c418a0941c7497ece39ad89008a084aeddba97935e5158a095ea56bfce5024e9f008a0894076c3bc5a9d72b8a08376e39db1e2c8a6d8a0982c47dc69701a288008a080a5558e826cbfd656c86522e"

payload = bytes.fromhex(hex_code)
pickletools.dis(payload)

extract_list = payload[:1854] + pickle.STOP

inp = b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

l = pickle.loads(extract_list)

print(l)

ctr_init = 1384596539316466481

_pts = []
for i in range(8):
    _pts.append(l[i] ^ ctr_init)
    ctr_init = (42 * ctr_init + 1337) & ((1 << 64)-1)

_pts[3], _pts[6] = _pts[6], _pts[3]

x = _pts[5]
known_bits = 0

while known_bits < 64:
    known_bits = min(known_bits + 12, 64)
    known_mask = ((1 << known_bits) - 1) << (64 - known_bits)
    known = x & known_mask
    key = known >> 12
    x = _pts[5] ^ key

_pts[5] = x

_pts[1] = _pts[1] ^ _pts[6]

mask = (1 << 61) - 1
msb13 = _pts[1] >> (64-13)
_pts[1] = (_pts[1] << 13) & mask
_pts[1] |= msb13

_pts[4] = -_pts[4] + 0x8080808080808080
_pts[2], _pts[7] = _pts[7], _pts[2]
_pts[0] ^= 0x1337deadc0de1337

from Crypto.Util.number import long_to_bytes
print(b"".join(long_to_bytes(pt) for pt in _pts))
```

## Flag

`Alpaca{not_only_the_cake,_varnames,_filenames_and_etc._are_lies}`

[^1]: 実はpickletools.pyも完全ではなく難読化を施されると途中で中断したりエラーを吐いて死ぬことがあるので、自作の実行時にログを取得するツールを使った
