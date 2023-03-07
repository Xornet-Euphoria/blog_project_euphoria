+++
title = "DiceCTF @ HOPE - better-llvm"
date = 2023-03-07

[taxonomies]
tags = ["CTF", "Writeup", "rev", "Python"]
+++

- 問題ファイル: [hope-2022-challenges/chall at master · dicegang/hope-2022-challenges](https://github.com/dicegang/hope-2022-challenges/tree/master/rev/better-llvm)

## TL;DR

- C言語でPythonのオブジェクトを扱っているバイナリが与えられる
- 入力後、定義された関数のコードオブジェクトを書き換えてから実行しており、書き換えられた関数が`True`を返すような入力を与えたい
- デコンパイル結果を読んでどのような関数になっているのかを特定するのは骨が折れるのでバイトコードを抽出する
- こいつを人力でデコンパイルして解析し、フラグを得る

## Prerequisite

- Pythonのバイトコード(`dis`の使い方も)

## Writeup

ELF(not stripped)が与えられるのでGhidraにぶち込んでデコンパイル結果を見ると、`fgets`で入力(但し21文字で1文字目がhである事が要求されている)を得てから、Pythonのオブジェクトを扱うような関数を呼んでいる。具体的に抜粋すると次のようになっている。

```c
    Py_Initialize();
    uVar6 = PyDict_New();
    uVar7 = PyDict_New();
    PyRun_StringFlags("def dicegang():\n x = input().encode()\n for (a, b) in zip(x, bytes.fromhex(\ '4e434e0a53455f0a584f4b4646530a5e424344410a435e0d4e0a484f0a5e424b5e0a4f4b5953\')):\n  if a ^ 42  != b:\n   return False\n return True"
                      ,0x101,uVar7,uVar6);
    uVar7 = PyUnicode_FromString("dicegang");
    uVar7 = PyDict_GetItem(uVar6,uVar7);
    lVar8 = PyFunction_GetCode(uVar7);
    uVar7 = PyTuple_New(0);

	/* ~~ snipped ~~ */

	uVar7 = PyBytes_FromStringAndSize(auStack_186d8,(long)(iVar16 + 4));
    *(undefined8 *)(lVar8 + 0x30) = uVar7;
    uVar7 = PyDict_New();
    PyRun_StringFlags("if dicegang():\n print(\'ok fine you got the flag\')\nelse:\n print(\'nope >: )\')"
	                  ,0x101,uVar7,uVar6,0);
    Py_Finalize();
```

`PyRun_StringFlags`という明らかに`exec`相当の事をしそうな関数があり、2つ目のこの関数の引数を見ると、1つ目のこの関数で定義された`dicegang()`関数がTrueを返すような入力を与えれば良いらしい。

というわけで`bytes.fromhex( '4e434e0a53455f0a584f4b4646530a5e424344410a435e0d4e0a484f0a5e424b5e0a4f4b5953')`の各バイトに42をXORしたバイト列がフラグに……ならない。`did you really think it'd be that easy`が出てくる(それはそう)。

1つ目の`PyRun_StringFlags`の後を雑に読んでみると関数`dicegang`に対して色々な操作をしている予感がするのでおそらく(Pythonの)バイトコードを書き換えたりしていると考えられる。↑では`~~ snipped ~~`で省略してしまったが、実はかなりの量の処理が存在しており、これを全部読んで理解するのは難しい。

しかし、`PyRun_StringFlags`は末尾にもう1つ存在しており、更にこの関数が引数にとった文字列をPythonのコードとして実行する事を考えると、ここを書き換えたら関数`dicegang`がどんなものであるかを調べられる予感がする。

というわけで次のようなコードで2つ目の`PyRun_StringFlags`の第1引数を変えたバイナリを用意して実行してみる。

```python
challname = "./chall"

with open(challname, "rb") as f:
    chall_bytes = f.read()

start = 0x20f8
end = 0x2143

py_code = chall_bytes[start:end]
print(py_code.decode())

new_code = "co=dicegang.__code__;print(co.co_code,co.co_consts,co.co_varnames)"
# new_code = "co=dicegang.__code__;print(co.co_cellvars,co.co_freevars,co.co_consts)"
# new_code = "import dis;print(dict(dis.findlinestarts(dicegang.__code__)))"
assert len(new_code) <= len(py_code), len(new_code)
new_code += "\x00" * (len(py_code) - len(new_code))

print(len(new_code))
print(new_code)

formar_bin = chall_bytes[:start]
latter_bin = chall_bytes[end:]
new_bin = formar_bin + new_code.encode() + latter_bin

assert len(new_bin) == len(chall_bytes)

with open(f"{challname}_new", "wb") as f:
    f.write(new_bin)

# execute

import os, subprocess
os.system("chmod +x ./chall_new")

subprocess.run(["./chall_new"], input=open("./input.txt", "rb").read())
```

これを実行すると、Pythonのバイトコード(`co.co_code`)や`LOAD_CONST`で読み込んでいる値(`co.co_consts`)等の情報が得られる。また、`import`も特に問題なく出来そうなので`import dis`してディスアセンブルすることも考えられる。

しかし、実際に`new_code = "import dis;dis.dis(dicegang)"`によってディスアセンブルを試みると、途中で次のようなエラーを吐かれる。

```txt
  2           0 LOAD_CONST               4 (0)
              2 LOAD_CONST               0 ('hope{XXXXXXXXXXXXXXX}')
              4 ROT_TWO
              6 BINARY_SUBSCR
              8 LOAD_CONST               1 ({'a': (13, 22), 'b': (-13, -9), 'c': (42, 15), 'd': (40, 0), 'e': (-47, 8), 'f': (-20, -29), 'g': (14, -36), 'h': (-1, 48), 'i': (9, -27), 'j': (42, -22), 'k': (-34, -9), 'l': (44, -5), 'm': (46, 1), 'n': (22, -39), 'o': (-25, 42), 'p': (-44, 14), 'q': (8, 14), 'r': (1, 2), 's': (-17, -39), 't': (-14, 31), 'u': (9, 21), 'v': (43, -18), 'w': (40, 12), 'x': (33, 9), 'y': (-28, 25), 'z': (10, -17), 'A': (35, -20), 'B': (4, -32), 'C': (-42, -22), 'D': (21, 19), 'E': (3, 26), 'F': (-8, -6), 'G': (-32, -2), 'H': (-18, -42), 'I': (27, -39), 'J': (-10, 26), 'K': (4, 41), 'L': (-21, 34), 'M': (-27, 10), 'N': (13, -47), 'O': (11, -47), 'P': (-33, -34), 'Q': (-13, -33), 'R': (26, -34), 'S': (36, -29), 'T': (-27, -40), 'U': (-13, -42), 'V': (42, 23), 'W': (-32, -24), 'X': (-12, -23), 'Y': (-29, -39), 'Z': (8, 30), '0': (34, 8), '1': (-37, -13), '2': (25, 38), '3': (-34, -7), '4': (-13, 13), '5': (1, -25), '6': (-30, 33), '7': (27, -10), '8': (-5, 37), '9': (37, 1), '_': (20, -46), '{': (-49, -2), '}': (9, 45)})

  3          10 ROT_TWO
             12 BINARY_SUBSCR
             14 UNPACK_SEQUENCE          2
Traceback (most recent call last):
  File "<string>", line 1, in <module>
  File "/usr/lib/python3.10/dis.py", line 79, in dis
    _disassemble_recursive(x, file=file, depth=depth)
  File "/usr/lib/python3.10/dis.py", line 376, in _disassemble_recursive
    disassemble(co, file=file)
  File "/usr/lib/python3.10/dis.py", line 372, in disassemble
    _disassemble_bytes(co.co_code, lasti, co.co_varnames, co.co_names,
  File "/usr/lib/python3.10/dis.py", line 404, in _disassemble_bytes
    for instr in _get_instructions_bytes(code, varnames, names,
  File "/usr/lib/python3.10/dis.py", line 348, in _get_instructions_bytes
    argval, argrepr = _get_name_info(arg, varnames)
  File "/usr/lib/python3.10/dis.py", line 304, in _get_name_info
    argval = name_list[name_index]
IndexError: tuple index out of range
```

どうやら、変数の参照が失敗しているようである。上記の抽出コードでも`co_varnames`は空のタプルを出力していたのでこれが原因で`IndexError`を起こしていると考えられる。ただ、これは`dis`の事情なのでこのバイトコード自体は普通に実行出来るはずである。

ところで`dis.dis`は関数だけでなく、生のバイト列も引数として渡すことが出来て、この場合はバイト列をバイトコードとみなしてディスアセンブルを行う。[CPythonの実装](https://github.com/python/cpython/blob/3.10/Lib/dis.py#L80)を見ると、特に`co_varnames`といったものを渡す必要は無さそうなのでこれでディスアセンブルしてみると次が得られる。

```
          0 LOAD_CONST               4 (4)
          2 LOAD_CONST               0 (0)
          4 ROT_TWO
          6 BINARY_SUBSCR
          8 LOAD_CONST               1 (1)
         10 ROT_TWO
         12 BINARY_SUBSCR
         14 UNPACK_SEQUENCE          2
         16 STORE_FAST               0 (0)
         18 STORE_FAST               1 (1)
         20 LOAD_CONST               5 (5)
         22 LOAD_CONST               6 (6)
         24 BUILD_SLICE              0
         26 LOAD_CONST               0 (0)
         28 ROT_TWO
         30 BINARY_SUBSCR
         32 GET_ITER
    >>   34 FOR_ITER                57 (to 150)
         36 LOAD_CONST               1 (1)
         38 ROT_TWO
         40 BINARY_SUBSCR
         42 UNPACK_SEQUENCE          2
         44 STORE_FAST               2 (2)
         46 STORE_FAST               3 (3)

		/* ~~snipped ~~ */

        142 STORE_FAST               0 (0)
        144 LOAD_FAST                3 (3)
        146 STORE_FAST               1 (1)
        148 JUMP_ABSOLUTE           17 (to 34)
    >>  150 LOAD_CONST               3 (3)
        152 RETURN_VALUE
```

先程の結果と比較すると、`16 STORE_FAST 0 (0)`以降が生えており、やっぱりローカル変数を参照出来なくて落ちていた事がわかる。

さて、これでバイトコードが何をしているかがわかったので素直にデコンパイルしていけば良いのだが、これだとあまりにも可読性が低く、特に`co_consts`や変数名を指定していないせいでこれらが表示されないのが大きい。というわけでいい感じにコードオブジェクトを構成して`dis.dis`に渡して可読性の高いディスアセンブル結果を得たい。

再びCPythonの実装を追ってみると[`_disassemble_bytes`](https://github.com/python/cpython/blob/3.10/Lib/dis.py#L386)という関数が用意されているので、これを読んでいる`disassemble`関数等を参考にしながら必要な情報を先程のスクリプトで集め、`co_varnames`を適当に定義し(上記ディスアセンブル結果からローカル変数は6つっぽい)、次のスクリプトでディスアセンブルを試みる。

```python
import dis

co_code = b'd\x04d\x00\x02\x00\x19\x00d\x01\x02\x00\x19\x00\\\x02}\x00}\x01d\x05d\x06\x85\x00d\x00\x02\x00\x19\x00D\x00]9d\x01\x02\x00\x19\x00\\\x02}\x02}\x03|\x02|\x00\x18\x00}\x02|\x03|\x01\x18\x00}\x03d\x01D\x00]\x1bd\x01\x02\x00\x19\x00\\\x02}\x04}\x05|\x04|\x00\x18\x00}\x04|\x05|\x01\x18\x00}\x05|\x02|\x05\x14\x00|\x03|\x04\x14\x00\x18\x00d\x04k\x05s=d\x02S\x00q"|\x02|\x00\x17\x00}\x02|\x03|\x01\x17\x00}\x03|\x02}\x00|\x03}\x01q\x11d\x03S\x00'
lasti = -1
co_varnames = tuple(f"v_{i}" for i in range(6))
co_names = ()
flag = 'hope{XXXXXXXXXXXXXXX}'
co_consts = (flag , {'a': (13, 22), 'b': (-13, -9), 'c': (42, 15), 'd': (40, 0), 'e': (-47, 8), 'f': (-20, -29), 'g': (14, -36), 'h': (-1, 48), 'i': (9, -27), 'j': (42, -22), 'k': (-34, -9), 'l': (44, -5), 'm': (46, 1), 'n': (22, -39), 'o': (-25, 42), 'p': (-44, 14), 'q': (8, 14), 'r': (1, 2), 's': (-17, -39), 't': (-14, 31), 'u': (9, 21), 'v': (43, -18), 'w': (40, 12), 'x': (33, 9), 'y': (-28, 25), 'z': (10, -17), 'A': (35, -20), 'B': (4, -32), 'C': (-42, -22), 'D': (21, 19), 'E': (3, 26), 'F': (-8, -6), 'G': (-32, -2), 'H': (-18, -42), 'I': (27, -39), 'J': (-10, 26), 'K': (4, 41), 'L': (-21, 34), 'M': (-27, 10), 'N': (13, -47), 'O': (11, -47), 'P': (-33, -34), 'Q': (-13, -33), 'R': (26, -34), 'S': (36, -29), 'T': (-27, -40), 'U': (-13, -42), 'V': (42, 23), 'W': (-32, -24), 'X': (-12, -23), 'Y': (-29, -39), 'Z': (8, 30), '0': (34, 8), '1': (-37, -13), '2': (25, 38), '3': (-34, -7), '4': (-13, 13), '5': (1, -25), '6': (-30, 33), '7': (27, -10), '8': (-5, 37), '9': (37, 1), '_': (20, -46), '{': (-49, -2), '}': (9, 45)}, False, True, 0, 1, None)
cell_names = ()
linestarts = {0: 2, 10: 3, 34: 4, 46: 5, 52: 4, 54: 6}
file=None

# https://github.com/python/cpython/blob/3.10/Lib/dis.py#L386
dis._disassemble_bytes(co_code, lasti, co_varnames, co_names, co_consts, cell_names, linestarts, file=file)
```

これを実行すると次のような完全体のディスアセンブル結果が得られる。

```
  2           0 LOAD_CONST               4 (0)
              2 LOAD_CONST               0 ('hope{XXXXXXXXXXXXXXX}')
              4 ROT_TWO
              6 BINARY_SUBSCR
              8 LOAD_CONST               1 ({'a': (13, 22), 'b': (-13, -9), 'c': (42, 15), 'd': (40, 0), 'e': (-47, 8), 'f': (-20, -29), 'g': (14, -36), 'h': (-1, 48), 'i': (9, -27), 'j': (42, -22), 'k': (-34, -9), 'l': (44, -5), 'm': (46, 1), 'n': (22, -39), 'o': (-25, 42), 'p': (-44, 14), 'q': (8, 14), 'r': (1, 2), 's': (-17, -39), 't': (-14, 31), 'u': (9, 21), 'v': (43, -18), 'w': (40, 12), 'x': (33, 9), 'y': (-28, 25), 'z': (10, -17), 'A': (35, -20), 'B': (4, -32), 'C': (-42, -22), 'D': (21, 19), 'E': (3, 26), 'F': (-8, -6), 'G': (-32, -2), 'H': (-18, -42), 'I': (27, -39), 'J': (-10, 26), 'K': (4, 41), 'L': (-21, 34), 'M': (-27, 10), 'N': (13, -47), 'O': (11, -47), 'P': (-33, -34), 'Q': (-13, -33), 'R': (26, -34), 'S': (36, -29), 'T': (-27, -40), 'U': (-13, -42), 'V': (42, 23), 'W': (-32, -24), 'X': (-12, -23), 'Y': (-29, -39), 'Z': (8, 30), '0': (34, 8), '1': (-37, -13), '2': (25, 38), '3': (-34, -7), '4': (-13, 13), '5': (1, -25), '6': (-30, 33), '7': (27, -10), '8': (-5, 37), '9': (37, 1), '_': (20, -46), '{': (-49, -2), '}': (9, 45)})

  3          10 ROT_TWO
             12 BINARY_SUBSCR
             14 UNPACK_SEQUENCE          2
             16 STORE_FAST               0 (v_0)
             18 STORE_FAST               1 (v_1)
             20 LOAD_CONST               5 (1)
             22 LOAD_CONST               6 (None)
             24 BUILD_SLICE              0
             26 LOAD_CONST               0 ('hope{XXXXXXXXXXXXXXX}')
             28 ROT_TWO
             30 BINARY_SUBSCR
             32 GET_ITER

  4     >>   34 FOR_ITER                57 (to 150)
             36 LOAD_CONST               1 ({'a': (13, 22), 'b': (-13, -9), 'c': (42, 15), 'd': (40, 0), 'e': (-47, 8), 'f': (-20, -29), 'g': (14, -36), 'h': (-1, 48), 'i': (9, -27), 'j': (42, -22), 'k': (-34, -9), 'l': (44, -5), 'm': (46, 1), 'n': (22, -39), 'o': (-25, 42), 'p': (-44, 14), 'q': (8, 14), 'r': (1, 2), 's': (-17, -39), 't': (-14, 31), 'u': (9, 21), 'v': (43, -18), 'w': (40, 12), 'x': (33, 9), 'y': (-28, 25), 'z': (10, -17), 'A': (35, -20), 'B': (4, -32), 'C': (-42, -22), 'D': (21, 19), 'E': (3, 26), 'F': (-8, -6), 'G': (-32, -2), 'H': (-18, -42), 'I': (27, -39), 'J': (-10, 26), 'K': (4, 41), 'L': (-21, 34), 'M': (-27, 10), 'N': (13, -47), 'O': (11, -47), 'P': (-33, -34), 'Q': (-13, -33), 'R': (26, -34), 'S': (36, -29), 'T': (-27, -40), 'U': (-13, -42), 'V': (42, 23), 'W': (-32, -24), 'X': (-12, -23), 'Y': (-29, -39), 'Z': (8, 30), '0': (34, 8), '1': (-37, -13), '2': (25, 38), '3': (-34, -7), '4': (-13, 13), '5': (1, -25), '6': (-30, 33), '7': (27, -10), '8': (-5, 37), '9': (37, 1), '_': (20, -46), '{': (-49, -2), '}': (9, 45)})
             38 ROT_TWO
             40 BINARY_SUBSCR
             42 UNPACK_SEQUENCE          2
             44 STORE_FAST               2 (v_2)

  5          46 STORE_FAST               3 (v_3)
             48 LOAD_FAST                2 (v_2)
             50 LOAD_FAST                0 (v_0)

  4          52 BINARY_SUBTRACT

  6          54 STORE_FAST               2 (v_2)
             56 LOAD_FAST                3 (v_3)
             58 LOAD_FAST                1 (v_1)
             60 BINARY_SUBTRACT
             62 STORE_FAST               3 (v_3)
             64 LOAD_CONST               1 ({'a': (13, 22), 'b': (-13, -9), 'c': (42, 15), 'd': (40, 0), 'e': (-47, 8), 'f': (-20, -29), 'g': (14, -36), 'h': (-1, 48), 'i': (9, -27), 'j': (42, -22), 'k': (-34, -9), 'l': (44, -5), 'm': (46, 1), 'n': (22, -39), 'o': (-25, 42), 'p': (-44, 14), 'q': (8, 14), 'r': (1, 2), 's': (-17, -39), 't': (-14, 31), 'u': (9, 21), 'v': (43, -18), 'w': (40, 12), 'x': (33, 9), 'y': (-28, 25), 'z': (10, -17), 'A': (35, -20), 'B': (4, -32), 'C': (-42, -22), 'D': (21, 19), 'E': (3, 26), 'F': (-8, -6), 'G': (-32, -2), 'H': (-18, -42), 'I': (27, -39), 'J': (-10, 26), 'K': (4, 41), 'L': (-21, 34), 'M': (-27, 10), 'N': (13, -47), 'O': (11, -47), 'P': (-33, -34), 'Q': (-13, -33), 'R': (26, -34), 'S': (36, -29), 'T': (-27, -40), 'U': (-13, -42), 'V': (42, 23), 'W': (-32, -24), 'X': (-12, -23), 'Y': (-29, -39), 'Z': (8, 30), '0': (34, 8), '1': (-37, -13), '2': (25, 38), '3': (-34, -7), '4': (-13, 13), '5': (1, -25), '6': (-30, 33), '7': (27, -10), '8': (-5, 37), '9': (37, 1), '_': (20, -46), '{': (-49, -2), '}': (9, 45)})
             66 GET_ITER
        >>   68 FOR_ITER                27 (to 124)
             70 LOAD_CONST               1 ({'a': (13, 22), 'b': (-13, -9), 'c': (42, 15), 'd': (40, 0), 'e': (-47, 8), 'f': (-20, -29), 'g': (14, -36), 'h': (-1, 48), 'i': (9, -27), 'j': (42, -22), 'k': (-34, -9), 'l': (44, -5), 'm': (46, 1), 'n': (22, -39), 'o': (-25, 42), 'p': (-44, 14), 'q': (8, 14), 'r': (1, 2), 's': (-17, -39), 't': (-14, 31), 'u': (9, 21), 'v': (43, -18), 'w': (40, 12), 'x': (33, 9), 'y': (-28, 25), 'z': (10, -17), 'A': (35, -20), 'B': (4, -32), 'C': (-42, -22), 'D': (21, 19), 'E': (3, 26), 'F': (-8, -6), 'G': (-32, -2), 'H': (-18, -42), 'I': (27, -39), 'J': (-10, 26), 'K': (4, 41), 'L': (-21, 34), 'M': (-27, 10), 'N': (13, -47), 'O': (11, -47), 'P': (-33, -34), 'Q': (-13, -33), 'R': (26, -34), 'S': (36, -29), 'T': (-27, -40), 'U': (-13, -42), 'V': (42, 23), 'W': (-32, -24), 'X': (-12, -23), 'Y': (-29, -39), 'Z': (8, 30), '0': (34, 8), '1': (-37, -13), '2': (25, 38), '3': (-34, -7), '4': (-13, 13), '5': (1, -25), '6': (-30, 33), '7': (27, -10), '8': (-5, 37), '9': (37, 1), '_': (20, -46), '{': (-49, -2), '}': (9, 45)})
             72 ROT_TWO
             74 BINARY_SUBSCR
             76 UNPACK_SEQUENCE          2
             78 STORE_FAST               4 (v_4)
             80 STORE_FAST               5 (v_5)
             82 LOAD_FAST                4 (v_4)
             84 LOAD_FAST                0 (v_0)
             86 BINARY_SUBTRACT
             88 STORE_FAST               4 (v_4)
             90 LOAD_FAST                5 (v_5)
             92 LOAD_FAST                1 (v_1)
             94 BINARY_SUBTRACT
             96 STORE_FAST               5 (v_5)
             98 LOAD_FAST                2 (v_2)
            100 LOAD_FAST                5 (v_5)
            102 BINARY_MULTIPLY
            104 LOAD_FAST                3 (v_3)
            106 LOAD_FAST                4 (v_4)
            108 BINARY_MULTIPLY
            110 BINARY_SUBTRACT
            112 LOAD_CONST               4 (0)
            114 COMPARE_OP               5 (>=)
            116 POP_JUMP_IF_TRUE        61 (to 122)
            118 LOAD_CONST               2 (False)
            120 RETURN_VALUE
        >>  122 JUMP_ABSOLUTE           34 (to 68)
        >>  124 LOAD_FAST                2 (v_2)
            126 LOAD_FAST                0 (v_0)
            128 BINARY_ADD
            130 STORE_FAST               2 (v_2)
            132 LOAD_FAST                3 (v_3)
            134 LOAD_FAST                1 (v_1)
            136 BINARY_ADD
            138 STORE_FAST               3 (v_3)
            140 LOAD_FAST                2 (v_2)
            142 STORE_FAST               0 (v_0)
            144 LOAD_FAST                3 (v_3)
            146 STORE_FAST               1 (v_1)
            148 JUMP_ABSOLUTE           17 (to 34)
        >>  150 LOAD_CONST               3 (True)
            152 RETURN_VALUE

```

というわけでこれをデコンパイルする。pyc等だったらuncompyle6が使えた可能性もあるが、バイトコードやコードオブジェクトのままでデコンパイルする方法はちょっと考えただけだと思いつかなかったので[^1]いつものように人力デコンパイルをする。次のようなコードにデコンパイルした。

```python
import dis

d = {'a': (13, 22), 'b': (-13, -9), 'c': (42, 15), 'd': (40, 0), 'e': (-47, 8), 'f': (-20, -29), 'g': (14, -36), 'h': (-1, 48), 'i': (9, -27), 'j': (42, -22), 'k': (-34, -9), 'l': (44, -5), 'm': (46, 1), 'n': (22, -39), 'o': (-25, 42), 'p': (-44, 14), 'q': (8, 14), 'r': (1, 2), 's': (-17, -39), 't': (-14, 31), 'u': (9, 21), 'v': (43, -18), 'w': (40, 12), 'x': (33, 9), 'y': (-28, 25), 'z': (10, -17), 'A': (35, -20), 'B': (4, -32), 'C': (-42, -22), 'D': (21, 19), 'E': (3, 26), 'F': (-8, -6), 'G': (-32, -2), 'H': (-18, -42), 'I': (27, -39), 'J': (-10, 26), 'K': (4, 41), 'L': (-21, 34), 'M': (-27, 10), 'N': (13, -47), 'O': (11, -47), 'P': (-33, -34), 'Q': (-13, -33), 'R': (26, -34), 'S': (36, -29), 'T': (-27, -40), 'U': (-13, -42), 'V': (42, 23), 'W': (-32, -24), 'X': (-12, -23), 'Y': (-29, -39), 'Z': (8, 30), '0': (34, 8), '1': (-37, -13), '2': (25, 38), '3': (-34, -7), '4': (-13, 13), '5': (1, -25), '6': (-30, 33), '7': (27, -10), '8': (-5, 37), '9': (37, 1), '_': (20, -46), '{': (-49, -2), '}': (9, 45)}

def dicegang():
    s = "hope{XXXXXXXXXXXXXXX}"  # input

    v_0, v_1 = d[s[0]]
    for c in s[1:None]:
        v_2, v_3 = d[c]
        v_2 = v_2 - v_0
        v_3 = v_3 - v_1
        for k in d:
            v_4, v_5 = d[k]
            v_4 = v_4 - v_0
            v_5 = v_5 - v_1
            if v_2 * v_5 - v_3 * v_4 >= 0:
                continue
            return False
        v_2 = v_2 + v_0
        v_3 = v_3 + v_1
        v_0 = v_2
        v_1 = v_3

    return True

# check
# dis.dis(dicegang)
```

これがTrueを返すような入力(フラグ)を考える。フラグの先頭がhである事はわかっているので、`c = 'h'`に対して2つ目のfor文が`False`を返さず通過するような文字を探索する。このコードの都合上、`h`を21文字並べたような「途中まで正解で以降全て同じ文字からなる文字列」といった入力は`v_2, v_3`がいずれも0になって通過してしまうのでそういったものはフラグにならないという仮定をおいている[^2]。これを繰り返すことで先頭から文字を確定させていくとフラグが得られる。次のようなコードを用いた。

```python
d = {'a': (13, 22), 'b': (-13, -9), 'c': (42, 15), 'd': (40, 0), 'e': (-47, 8), 'f': (-20, -29), 'g': (14, -36), 'h': (-1, 48), 'i': (9, -27), 'j': (42, -22), 'k': (-34, -9), 'l': (44, -5), 'm': (46, 1), 'n': (22, -39), 'o': (-25, 42), 'p': (-44, 14), 'q': (8, 14), 'r': (1, 2), 's': (-17, -39), 't': (-14, 31), 'u': (9, 21), 'v': (43, -18), 'w': (40, 12), 'x': (33, 9), 'y': (-28, 25), 'z': (10, -17), 'A': (35, -20), 'B': (4, -32), 'C': (-42, -22), 'D': (21, 19), 'E': (3, 26), 'F': (-8, -6), 'G': (-32, -2), 'H': (-18, -42), 'I': (27, -39), 'J': (-10, 26), 'K': (4, 41), 'L': (-21, 34), 'M': (-27, 10), 'N': (13, -47), 'O': (11, -47), 'P': (-33, -34), 'Q': (-13, -33), 'R': (26, -34), 'S': (36, -29), 'T': (-27, -40), 'U': (-13, -42), 'V': (42, 23), 'W': (-32, -24), 'X': (-12, -23), 'Y': (-29, -39), 'Z': (8, 30), '0': (34, 8), '1': (-37, -13), '2': (25, 38), '3': (-34, -7), '4': (-13, 13), '5': (1, -25), '6': (-30, 33), '7': (27, -10), '8': (-5, 37), '9': (37, 1), '_': (20, -46), '{': (-49, -2), '}': (9, 45)}


def search(x, v_0, v_1):
    ret = []
    for c in d:
        is_ok = True
        v_2, v_3 = d[c]
        v_2 -= v_0
        v_3 -= v_1
        for k in d:
            v_4, v_5 = d[k]
            v_4 -= v_0
            v_5 -= v_1
            if v_2 * v_5 - v_3 * v_4 >= 0:
                continue
            is_ok = False
            break

        if is_ok and c != x:
            ret.append(c)

    return ret

flag = "h"

c = "h"
v_0, v_1 = d[c]

for i in range(1, 0x15):
    res = search(c, v_0, v_1)
    if len(res) != 1:
        print(c, res)
        break

    c = res.pop()
    flag += c

    v_0, v_1 = d[c]

print(flag)

```

## Flag

`hope{CPYTHON_ISjvmV2}`

## References

- [dis --- Python バイトコードの逆アセンブラ — Python 3.10.10 ドキュメント](https://docs.python.org/ja/3.10/library/dis.html)
	- この問題はPython3.10でテストされている旨がdescriptionにあった
- [cpython/dis.py at 3.10 · python/cpython](https://github.com/python/cpython/blob/3.10/Lib/dis.py)
- [DiceCTF @ HOPE WriteUps | 廢文集中區](https://blog.maple3142.net/2022/07/24/dicectf-at-hope-writeups/#better-llvm)
	- maple3142さんのWriteup
	- `PyRun_StringFlags`に`"exec(input())"`を渡すことで特に文字数を気にせず任意のコードを実行出来るという天才アイデア

[^1]: 知ってたら教えてください

[^2]: 実際`'h' * 21`のような入力を与えると合っている旨のメッセージが出てくるが、もちろんフラグではないはずである