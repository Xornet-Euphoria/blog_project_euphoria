+++
title = "SECCON CTF 2020 - SCSBX:Reversing"
date = 2023-03-07

[taxonomies]
tags = ["CTF", "Writeup", "rev", "VM"]
+++

- 問題ファイル: <https://github.com/SECCON/SECCON2020_online_CTF/tree/main/reversing/scsbx_reversing/files>

## TL;DR

- 単純なスタックマシンが実装されており、その上で動くバイナリが与えられ、このバイナリでCrackMeを解く
- エミュレータを書き、実行トレースを入手して解析する
- z3でフラグを求める

## Writeup

簡単なスタックマシンが実装されており、嬉しいことにVMの仕様書やソースコード、Makefileまで与えられている。ソースコードを改造して実行トレースを得たりスタックの中身を覗いたり[^1]すれば解析は簡単に出来るが、修行のためにこれは封じて解いてみる。

VMのバイナリを実行してみると`FLAG: `という出力の後に入力を要求され、適当に入れると`Wrong!!`が出力される。雑に実装したディスアセンブラを使ってバイナリを雑に読んでみると、入力が合っていると`Correct`が出力されるようである。

最初はディスアセンブラを書いて、それにVMで書かれたバイナリを食わせた結果を眺めていたが、デコンパイルに慣れてしまった貧弱Rev脳では何が起こっているのかを把握するのが難しかったので実行トレースを得る事を考える。

VMの命令は実行される度に、VM内の関数である`__cpu_exec(ins)`を呼び出すので、ここにブレークポイントを張って、ヒットする度にどの命令が実行されたのかを調べるコードをGDB Scriptで書く。

これで実際にどんな命令が実行されるのかはわかるが、レジスタにはプログラムカウンタとオペコードぐらいしか情報が残っていない。特に、各命令が実行された時のスタックの様子や実際の計算で用いられた引数と結果を知りたいが、そこまで追うのは難しいのでエミュレータを書いて詳細な実行トレースを得るという方針をとった。

これを眺めるとだいたい次のような処理を行う

1. メモリ上に32bitの数値を16個格納する(`arr`とおく)
2. 64バイトの入力をメモリに格納する
3. 入力を8バイトずつ区切って(これを`b`とおく)次の事を8ラウンド行う
	1. 線形合同法っぽいPRNG(パラメータとシード値は公開されている)から値を得る(`r`とおく)
	2. `b`を2つの32bitの数値とみなして前半と後半にわける(それぞれ`b1, b2`とおく)
	3. `x1 := (~(r ^ b2)) ^ b1`を計算する
	4. 再びPRNGから値を得て`r`に代入する
	5. `x2 := (~(r ^ x1)) ^ b2`を計算する
	6. PRNGから値を得て`r`に代入する
	7. `x3 := (~(r ^ x2)) ^ x1`を計算する
	8. `b1`に`x2`を、`b2`に`x3`を代入する
4. 各`b1, b2`が`arr`の対応する値と等しいかチェックする
	1. 正確にはその差を計算した値を16個全ての値でORをとるのだが、この結果が0で無いと`Wrong`を出力するため全ての差が0である必要がある

ここまでわかれば、後はz3に任せてしませば良い。not演算(`~`)がPythonでは`0xffffffff`とのXORである事と、PRNG上の算術演算が32bit以上になるとオーバーフローする事に注意する。

## Code

### エミュレータ

`from instr import ...`という行があるが、`instr.py`で命令を扱う構造体を定義している

```python
from instr import Instruction, ope_to_byte
import sys

DEBUG = "-d" in sys.argv

with open("./seccon.bin", "rb") as f:
    raw_code = f.read()

# vm context
l = len(raw_code)
pc = 0
base = 0xdead0000  # `MAP` emulation
stack: list[int] = []
mem = [0 for _ in range(0x1000)]  # `MAP` emulation
exit_code = 0

# breakpoint (for debug)
stop = 114514
stop_count = 2
cnt = 0

while pc < l:
    if pc == stop:
        cnt += 1
        if cnt == stop_count:
            break
    note = ""
    ope = raw_code[pc]
    arg = None
    if ope == ope_to_byte["PUSH"]:
        arg = int.from_bytes(raw_code[pc+1:pc+5], "little")

    ins = Instruction(ope, arg, pc)

    if ope == ope_to_byte["PUSH"]:
        stack.append(arg)  # type: ignore
    elif ope == ope_to_byte["POP"]:
        v = stack.pop()
        note = f"poped: {v:x}"
    elif ope == ope_to_byte["DUP"]:
        ofs = stack.pop()
        stack.append(stack[-1-ofs])
    elif ope == ope_to_byte["MAP"]:
        stack.pop()
        stack.pop()
        pass
    elif ope == ope_to_byte["CALL"]:
        v = stack.pop() - 1
        stack.append(pc+1)
        pc = v
    elif ope == ope_to_byte["STORE32"]:
        addr = stack.pop()
        v = stack.pop()
        bv = v.to_bytes(4, "little")
        addr -= base
        note = f"{addr:x} <- {v:x}"
        for i in range(4):
            mem[addr + i] = bv[i]
            if DEBUG:
                print(f"  {hex(addr+i)} <- {hex(bv[i])}")
    elif ope == ope_to_byte["STORE16"]:
        addr = stack.pop()
        v = stack.pop()
        bv = v.to_bytes(2, "little")
        addr -= base
        for i in range(2):
            mem[addr + i] = bv[i]
            if DEBUG:
                print(f"  {hex(addr+i)} <- {hex(bv[i])}")
    elif ope == ope_to_byte["LOAD32"]:
        addr = stack.pop() - base
        v = mem[addr] + mem[addr + 1] * 0x100 + mem[addr + 2] * 0x10000 + mem[addr + 3] * 0x1000000
        stack.append(v)
        note = f"push {hex(v)} from {addr:x}"
    elif ope == ope_to_byte["LOAD64"]:
        addr = stack.pop() - base
        addr2 = addr + 4
        v = mem[addr2] + mem[addr2 + 1] * 0x100 + mem[addr2 + 2] * 0x10000 + mem[addr2 + 3] * 0x1000000
        stack.append(v)
        note = f"push {hex(v)} from {addr:x}"
        v = mem[addr] + mem[addr + 1] * 0x100 + mem[addr + 2] * 0x10000 + mem[addr + 3] * 0x1000000
        stack.append(v)
        note = f"push {hex(v)} from {addr:x}"
    elif ope == ope_to_byte["ADD"]:
        a = stack.pop()
        b = stack.pop()
        v = a + b
        v &= 0xffffffff
        stack.append(v)
        note = f"{a:x} + {b:x} = {v:x}"
    elif ope == ope_to_byte["SUB"]:
        a = stack.pop()
        b = stack.pop()
        stack.append(a - b)
        note = f"{a:x} - {b:x} = {a-b:x}"
    elif ope == ope_to_byte["MUL"]:
        a = stack.pop()
        b = stack.pop()
        v = a * b
        v &= 0xffffffff
        stack.append(v)
        note = f"{a:x} * {b:x} = {v:x}"
    elif ope == ope_to_byte["MOD"]:
        a = stack.pop()
        b = stack.pop()
        stack.append(a % b)
        note = f"{a:x} % {b:x} = {a % b:x}"
    elif ope == ope_to_byte["OR"]:
        a = stack.pop()
        b = stack.pop()
        stack.append(a | b)
        note = f"{a:x} | {b:x} = {a | b:x}"
    elif ope == ope_to_byte["XOR"]:
        a = stack.pop()
        b = stack.pop()
        stack.append(a ^ b)
        note = f"{a:x} ^ {b:x} = {a ^ b:x}"
    elif ope == ope_to_byte["NOT"]:
        a = stack.pop()
        v = a ^ 0xffffffff
        stack.append(v)
        note = f"~{a:x} = {v:x}"
    elif ope == ope_to_byte["XCHG"]:
        ofs = stack.pop()
        a = stack[-1-ofs]
        b = stack.pop()
        stack.append(a)
        stack[-1-ofs] = b
        note = f"{hex(a)}, {hex(b)} (offset: {ofs})"
    elif ope == ope_to_byte["JMP"]:
        pc = stack.pop() - 1
    elif ope == ope_to_byte["JEQ"]:
        t = stack.pop() - 1
        f = stack.pop() - 1
        a = stack.pop()
        b = stack.pop()
        pc = t if a == b else f
        note = f"jump to {a:x} == {b:x} ? {t} : {f}"
    elif ope == ope_to_byte["WRITE"]:
        addr = stack.pop() - base
        length = stack.pop()
        o = ""
        for i in range(addr, addr + length):
            o += chr(mem[i])

        print(o)
    elif ope == ope_to_byte["READ"]:
        addr = stack.pop() - base
        length = stack.pop()
        inp = input()[:length]
        inp += "\x00" * (length - len(inp))
        assert len(inp) == length
        for i, c in enumerate(inp):
            mem[addr + i] = ord(c)
    elif ope == ope_to_byte["EXIT"]:
        exit_code = stack.pop()
        break
    else:
        print(f"[!] unimplemented!!: {ope:x}")
        break

    print(ins, f"({note})" if note else "")

    pc += 5 if ope == ope_to_byte["PUSH"] else 1

print(f"[+] stopped at {pc}")

print(f"[+] stack")
for x in reversed(stack):
    print(hex(x))

exit()

print("[+] memory map")
for addr in range(0, 0x100, 4):
    print(hex(addr), list(map(hex, mem[addr:addr+4])))
```

### フラグ導出

```python
import z3


class PRNG():
    def __init__(self) -> None:
        self.state = 0x6d35bcd
        self.a = 0x77f
        self.b = 0x32a
        self.m = 0x305eb3ea

    def __next__(self) -> int:
        v = (self.state * self.a) & 0xffffffff
        v -= self.b
        v %= self.m

        self.state = v
        return v
    

prng = PRNG()

solver = z3.Solver()
bvs = [(z3.BitVec(f"{i}_1", 32), z3.BitVec(f"{i}_2", 32)) for i in range(8)]

    

target = [
    (0x46761223, 0x54bea5c5),
    (0x7a22e8f6, 0x5db493c9),
    (0x55d175e, 0x22fcd33),
    (0x42c46be6, 0x6d10a0e8),
    (0x53f4c278, 0x7279ec2a),
    (0x5491fb39, 0x49ac421f),
    (0x49ab3a37, 0x47855812),
    (0x5718bb05, 0x540fb5b),
]

for (bv1, bv2), (t1, t2) in zip(bvs, target):
    r = prng.__next__()
    x1 = r ^ bv2 ^ 0xffffffff ^ bv1
    r = prng.__next__()
    x2 = r ^ x1 ^ 0xffffffff ^ bv2
    solver.add(x2 == t1)
    r = prng.__next__()
    x3 = r ^ x2 ^ 0xffffffff ^ x1
    solver.add(x3 == t2)

print(solver.check())

flag = b""
model = solver.model()
for bv1, bv2 in bvs:
    c1 = model[bv1].as_long().to_bytes(4, "little")
    c2 = model[bv2].as_long().to_bytes(4, "little")
    flag += c1
    flag += c2

print(flag)
```

## Flag

`SECCON{TfuRYYVaz8Us696t3JWNxZZPsXEmdL7cCmgzpgxXKarUOnIwhSj9tQ}`

[^1]: 配布されたVMのバイナリでは使われていないが、スタックをダンプするという超便利なユーティリティ用の命令(`SHOW`)が存在する
