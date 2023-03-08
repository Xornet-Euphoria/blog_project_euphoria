+++
title = "SECCON CTF 2021 - pyast64++.rev"
date = 2023-03-08

[taxonomies]
tags = ["CTF", "Writeup", "rev"]
+++


- 問題ファイル: [SECCON2021_online_CTF/reversing/pyast64++.rev/files/pyast64.rev at main · SECCON/SECCON2021_online_CTF](https://github.com/SECCON/SECCON2021_online_CTF/tree/main/reversing/pyast64%2B%2B.rev/files/pyast64.rev)

## TL;DR

- PythonのASTを辿ってコンパイルするコンパイラとそれでコンパイルされたELFが与えられ、このELFでCrackMeを解く
- 配列の境界値チェック用のコードが生えているせいでデコンパイル結果の可読性が低いが、複数のツールを使って気合で読む
- 用いられている関数の逆演算は簡単に書けるのでこれを書いてフラグを得る

## Writeup

pyast64.pyというPythonのASTを辿りながらx86_64へコンパイルするコンパイラとそれによって生成されたnot strippedなバイナリが与えられる。

このコンパイラは配列に対して操作がある度に境界値チェック等を行い、もし違反している(長さ以上のインデックスを指定したり、配列型を指定するマジックナンバーが含まれていなかったり)場合は`int3`が実行されてしまう。おそらく同じコンパイラを扱っている別の問題の「pyast64++.pwn」の方ではOOBを簡単にさせないためのギミックとなっているのだが、このRev問題を解く上ではこいつが必要になることは全く無い。にも関わらず、このチェックを行うコードは存在しているのでデコンパイルされたコードの可読性は著しく下がる。

幸いにも、コンパイラのソースコードが公開されているので、ディスアセンブル結果とコンパイラのコードを眺めながら、デコンパイル結果で必要そうなところだけをかいつまんで読んでいく。

配布されたコンパイラのコードによれば、配列を次のように表している。

```python
    def builtin_array(self, args):
        """FIXED: Nov 20th, 2021
        The original design of `array` was vulnerable to out-of-bounds access
        and type confusion. The fixed version of the array has its length
        to prevent out-of-bounds access.

        i.e. x=array(1)
         0        4        8        16
         +--------+--------+--------+
         | length |  type  |  x[0]  |
         +--------+--------+--------+

        The `type` field is used to check if the variable is actually an array.
        This value is not guessable.
        """
        assert len(args) == 1, 'array(len) expected 1 arg, not {}'.format(len(args))
        self.visit(args[0])
        # Array length must be within [0, 0xffff]
        self.asm.instr('popq', '%rax')
        self.asm.instr('cmpq', '$0xffff', '%rax')
        self.asm.instr('ja', 'trap')
        # Allocate array on stack, add size to _array_size
        self.asm.instr('movq', '%rax', '%rcx')
        self.asm.instr('addq', '$1', '%rax')
        self.asm.instr('shlq', '$3', '%rax')
        offset = self.local_offset('_array_size')
        self.asm.instr('addq', '%rax', '{}(%rbp)'.format(offset))
        self.asm.instr('subq', '%rax', '%rsp')
        self.asm.instr('movq', '%rsp', '%rax')
        self.asm.instr('movq', '%rax', '%rbx')
        # Store the array length
        self.asm.instr('mov', '%ecx', '(%rax)')
        self.asm.instr('movq', '%fs:0x2c', '%rdx')
        self.asm.instr('mov', '%edx', '4(%rax)')
        # Fill the buffer with 0x00
        self.asm.instr('lea', '8(%rax)', '%rdi')
        self.asm.instr('xor', '%eax', '%eax')
        self.asm.instr('rep', 'stosq')
        # Push address
        self.asm.instr('pushq', '%rbx')

```

この構造から、配列の本体は`length`とマジックナンバーである`type`の後に存在する。Ghidra等に構造体を定義して読ませれば可読性が上がった可能性もあるが、面倒なのでしなかった(なお、却って面倒になった可能性が高い)。

更に参照時は次のようなコンパイルが行われる(下記コードの`isinstance(target, ast.Subscript)`がTrueになる分岐)。

```python
    def visit_Assign(self, node):
        # Only supports assignment of (a single) local variable
        assert len(node.targets) == 1, \
            'can only assign one variable at a time'
        self.visit(node.value)
        target = node.targets[0]
        if isinstance(target, ast.Subscript):
            # array[offset] = value
            self.visit(target.slice) # Modified for Python 3.9
            self.asm.instr('popq', '%rax')
            self.asm.instr('popq', '%rbx')
            local_offset = self.local_offset(target.value.id)
            self.asm.instr('movq', '{}(%rbp)'.format(local_offset), '%rdx')
            # Make sure the target variable is array
            self.asm.instr('mov', '4(%rdx)', '%edi')
            self.asm.instr('mov', '%fs:0x2c', '%esi')
            self.asm.instr('cmp', '%edi', '%esi')
            self.asm.instr('jnz', 'trap')
            # Bounds checking
            self.asm.instr('mov', '(%rdx)', '%ecx')
            self.asm.instr('cmpq', '%rax', '%rcx')
            self.asm.instr('jbe', 'trap')
            # Store the element
            self.asm.instr('movq', '%rbx', '8(%rdx,%rax,8)')
        else:
            # variable = value
            offset = self.local_offset(node.targets[0].id)
            self.asm.instr('popq', '{}(%rbp)'.format(offset))
```

というわけで、配列参照の度にこのチェックが行われてデコンパイル結果が大変な事になるが、なんとか気合で読む。

バイナリ中で重要なのは`check`関数(とその中で呼ばれている関数群)で途中まではなんとか気合で読めるようになっている。

前半では後で出てくる`S`関数で用いられるSBOXを生成するための処理が走る。ここでは2つの数字`i,j`と配列`arr`を受け取って`arr[i]`と`arr[j]`の値を交換する関数`f`が使われていたりするが、入力に依存しないようなので`S`を呼び出す直前辺りでブレークポイントを張ってGDBスクリプトで値を抽出した。

後半は次のような処理になる。

```python
def check(l, inp):
    arr = b"SECCON2021"

    # ~~ create sbox (but snipped) ~~

    for i in range(10):
        S(len(inp), inp, sbox) # -> inp[i] = sbox[inp[i]]
        P(len(inp), inp)
        for j in range(l):
            inp[j] ^= arr[i]

	compare(inp)
```

問題なのは`P`関数でGhidraのデコンパイル結果を眺めると読むだけで一生が終わりそうな量の行が現れる。ここで途方に暮れてしまったので[作問者Writeup](https://ptr-yudai.hatenablog.com/entry/2021/12/19/232158#Reversing-210pts-pyast64rev)を覗いたところ、どうやらIDAだとかなり良い感じのデコンパイル結果が得られるらしい。そういえばIDA Freewareにもデコンパイル機能が付いたらしいので実際に使ってみると、相変わらず読み辛いものの、Ghidraよりは遥かにまともな結果が得られた[^1]。`P`とその内部で呼ばれている`FY`は次のような事をしている。

```python
def FY(arr) -> None:
    for i in range(0x40):
        f(i, i**3 % 67 % 64, arr)


def P(l, arr) -> None:
    for i in range(l // 8):
        # v71: builtin_array
        new_arr = [0 for _ in range(0x40)]
        for j in range(0x8):
            v67 = j + i*8
            v75 = arr[v67]
            # v75を低いビットから入れていく
            for k in range(0x8):
                v68 = k + 8*j
                new_arr[v68] = v75 % 2
                v75 //= 2

        FY(new_arr)
        # さっきのfor文の逆演算 (FYでごちゃ混ぜになっているのでrecoverではない)
        for j in range(0x8):
            v75 = 0
            v73 = 1
            for k in range(8):
                v69 = k + 8*j
                v75 |= new_arr[v69] * v73
                v73 *= 2
            v70 = j + i*8
            arr[v70] = v75
```

最後に一連の処理で変形された配列を`compare`関数に渡して、別の配列と1つずつ比較している。デコンパイル結果が健気にも大量のif文(64文字なので64個)で対応する値が何であるかを表示してくれたが、それを手作業で1つ1つ配列にしていく作業はしたくなかったので、GDBで比較する配列をダンプした。

というわけで`F`も`FY`も`S`も`P`も逆算可能で、目標の配列も得られたのでこれを逆算するコードを書く。

## Code

```python
sbox = [243, 106, 132, 232, 161, 31, 46, 140, 221, 19, 203, 158, 173, 183, 157, 76, 43, 237, 13, 209, 130, 81, 39, 235, 198, 122, 123, 77, 62, 63, 79, 146, 196, 215, 93, 145, 38, 187, 2, 14, 163, 195, 171, 242, 178, 167, 164, 236, 220, 212, 102, 3, 162, 192, 168, 230, 153, 252, 124, 229, 210, 159, 71, 45, 34, 6, 127, 84, 143, 113, 57, 96, 66, 100, 44, 204, 30, 87, 250, 185, 118, 131, 65, 47, 174, 54, 24, 98, 137, 213, 69, 52, 223, 110, 129, 255, 75, 53, 99, 36, 58, 197, 251, 175, 244, 51, 21, 217, 211, 169, 201, 141, 234, 83, 16, 49, 12, 92, 1, 166, 8, 206, 186, 126, 239, 240, 108, 29, 144, 194, 238, 105, 120, 224, 179, 32, 119, 228, 138, 231, 125, 26, 165, 133, 73, 40, 107, 249, 227, 248, 74, 176, 184, 20, 10, 116, 78, 80, 111, 60, 155, 104, 41, 68, 33, 142, 112, 59, 136, 149, 85, 128, 48, 177, 0, 150, 241, 94, 72, 160, 253, 139, 135, 154, 56, 233, 7, 11, 28, 202, 172, 27, 50, 82, 246, 193, 205, 22, 200, 247, 9, 208, 216, 115, 121, 189, 190, 134, 218, 152, 219, 5, 15, 86, 61, 23, 188, 35, 117, 88, 151, 4, 70, 207, 89, 180, 222, 214, 55, 245, 156, 91, 226, 254, 191, 181, 182, 148, 170, 225, 199, 97, 67, 101, 64, 103, 114, 25, 147, 18, 95, 42, 37, 17, 109, 90]


def f(i, j, l) -> None:
    l[i], l[j] = l[j], l[i]


def S(l, arr, arr2) -> None:
    for i in range(l):
        arr[i] = arr2[arr[i]]


def inv_S(l, arr, arr2) -> None:
    assert len(set(arr2)) == len(arr2)
    # inverse_sbox
    inv_sbox = [0 for _ in range(0x100)]
    for i, x in enumerate(arr2):
        inv_sbox[x] = i
    for i in range(l):
        arr[i] = inv_sbox[arr[i]]


def FY(arr) -> None:
    for i in range(0x40):
        f(i, i**3 % 67 % 64, arr)


def inv_FY(arr) -> None:
    for i in range(0x40 - 1, -1, -1):
        f(i, i**3 % 67 % 64, arr)


def P(l, arr) -> None:
    for i in range(l // 8):
        # v71: builtin_array
        new_arr = [0 for _ in range(0x40)]
        for j in range(0x8):
            v67 = j + i*8
            v75 = arr[v67]
            # v75を低いビットから入れていく
            for k in range(0x8):
                v68 = k + 8*j
                new_arr[v68] = v75 % 2
                v75 //= 2

        FY(new_arr)
        # さっきのfor文の逆演算 (FYでごちゃ混ぜになっているのでrecoverではない)
        for j in range(0x8):
            v75 = 0
            v73 = 1
            for k in range(8):
                v69 = k + 8*j
                v75 |= new_arr[v69] * v73
                v73 *= 2
            v70 = j + i*8
            arr[v70] = v75


def inv_P(l, arr) -> None:
    # 8つずつ処理しているので`i`をケツからやる必要は無さそう
    for i in range(l // 8):
        new_arr = [0 for _ in range(0x40)]
        for j in range(0x8):
            v67 = j + i*8
            v75 = arr[v67]
            # v75を低いビットから入れていく
            for k in range(0x8):
                v68 = k + 8*j
                new_arr[v68] = v75 % 2
                v75 //= 2

        inv_FY(new_arr)
        # さっきのfor文の逆演算 (FYでごちゃ混ぜになっているのでrecoverではない)
        for j in range(0x8):
            v75 = 0
            v73 = 1
            for k in range(8):
                v69 = k + 8*j
                v75 |= new_arr[v69] * v73
                v73 *= 2
            v70 = j + i*8
            arr[v70] = v75


def check(l, inp):
    arr = b"SECCON2021"
    # from: 16ef
    # arr2 = [0xff - i for i in range(0x100)]
    # in assembly, below codes are converted while-loop
    # js = [82, 149, 213, 20, 94, 166, 209, 249, 34, 73, 145, 202, 0, 53, 117, 179, 212, 242, 17, 46, 125, 172, 216, 3, 57, 109, 132, 152, 173, 192, 244, 25, 59, 92, 162, 204, 217, 227, 238, 247, 33, 60, 84, 107, 141, 173, 203, 203, 204, 203, 235, 252, 10, 63, 87, 109, 102, 125, 116, 132, 173, 180, 184, 237, 251, 7, 246, 226, 207, 186, 198, 195, 189, 246, 250, 252, 225, 195, 166, 135, 137, 124, 190, 173, 209, 201, 164, 157, 118, 77, 69, 46, 79, 52, 126, 108, 61, 11, 218, 167, 149, 116, 126, 89, 63, 35, 234, 238, 192, 185, 157, 114, 68, 21, 244, 206, 154, 187, 148, 77, 39, 242, 186, 129, 126, 179, 147, 67, 244, 169, 121, 58, 92, 25, 225, 223, 136, 103, 14, 179, 121, 145, 69, 248, 182, 215, 118, 84, 45, 249, 181, 98, 137, 50, 27, 205, 98, 35, 182, 71, 249, 156, 214, 117, 109, 21, 248, 196, 77, 2, 170, 67, 112, 95, 255, 157, 30, 156, 27, 192, 213, 131, 39, 178, 194, 216, 143, 176, 37, 13, 95, 228, 155, 28, 44, 44, 250, 100, 79, 184, 66, 49, 104, 121, 151, 73, 7, 242, 83, 89, 217, 74, 124, 129, 199, 232, 226, 63, 14, 99, 217, 64, 164, 151, 5, 204, 198, 208, 66, 141, 249, 86, 108, 197, 169, 196, 9, 43, 49, 114, 212, 39, 37, 116, 66, 154, 194, 202, 173, 247, 230, 234, 225, 38, 118, 21]
    # for i in range(0x100):
    #     # swap
    #     f(i, js[i], arr2)


    # fix length (but maybe unused if the input is equal to the flag)
    if l % 8 != 0:
        l = l + (8 - l % 8)

    for i in range(10):
        S(len(inp), inp, sbox) # -> _arr[_i] = _arr2[_arr[_i]]
        P(len(inp), inp)
        for j in range(l):
            inp[j] ^= arr[i]

    # compare()


def inv_check(l, arr):
    key = b"SECCON2021"

    for i in range(9, -1, -1):
        for j in range(l):
            arr[j] ^= key[i]
        inv_P(l, arr)
        inv_S(l, arr, sbox)

import random

def test():
    # test: FY
    arr = [random.randint(0x20, 0x7f) for _ in range(0x40)]
    cp_arr = [x for x in arr]

    FY(arr)
    inv_FY(arr)

    assert cp_arr == arr

    # test: S
    S(0x40, arr, sbox)
    inv_S(0x40, arr, sbox)

    assert cp_arr == arr

    # test: P
    P(0x40, arr)
    inv_P(0x40, arr)
    assert cp_arr == arr

    # test: check
    check(0x40, arr)
    inv_check(0x40, arr)
    assert cp_arr == arr


def recover():
    cmp = [
    0x000000000000004b, 0x00000000000000cb,
    0x00000000000000be, 0x000000000000007e,
    0x00000000000000b8, 0x00000000000000a9,
    0x000000000000001b, 0x000000000000004a,
    0x0000000000000023, 0x0000000000000053,
    0x0000000000000071, 0x0000000000000041,
    0x00000000000000cf, 0x00000000000000c1,
    0x000000000000001b, 0x0000000000000089,
    0x0000000000000025, 0x0000000000000062,
    0x0000000000000000, 0x0000000000000044,
    0x00000000000000db, 0x0000000000000071,
    0x0000000000000015, 0x00000000000000b4,
    0x00000000000000df, 0x0000000000000087,
    0x0000000000000005, 0x0000000000000081,
    0x00000000000000bd, 0x00000000000000c8,
    0x00000000000000f5, 0x0000000000000064,
    0x0000000000000075, 0x000000000000003e,
    0x00000000000000c0, 0x0000000000000065,
    0x00000000000000ef, 0x000000000000005c,
    0x00000000000000b6, 0x0000000000000088,
    0x000000000000009f, 0x00000000000000eb,
    0x00000000000000a6, 0x000000000000005a,
    0x000000000000004a, 0x0000000000000085,
    0x0000000000000053, 0x000000000000004e,
    0x0000000000000006, 0x00000000000000e1,
    0x0000000000000065, 0x0000000000000067,
    0x0000000000000052, 0x000000000000004e,
    0x0000000000000090, 0x00000000000000cd,
    0x0000000000000082, 0x00000000000000ee,
    0x00000000000000af, 0x00000000000000f5,
    0x00000000000000ac, 0x000000000000003e,
    0x000000000000009d, 0x00000000000000b0,
    ]

    inv_check(0x40, cmp)

    flag = ""
    for c in cmp:
        flag += chr(c)

    print(flag)

if __name__ == "__main__":
    test()
    recover()
```

## Flag

`SECCON{r3c3nt_d3c0mp1l3rs_R_g00d_4t_0pt1m1z1ng_PUSH-POP_p41rs}`

## References

- [SECCON CTF 2021作問者Writeup - CTFするぞ](https://ptr-yudai.hatenablog.com/entry/2021/12/19/232158#Reversing-210pts-pyast64rev)

---

[^1]: 但し、この問題において全ての関数でIDAの方が良いデコンパイル結果を出すかというとそうではなく、`FY`の引数を間違えていたり等の問題はあったので、両方見たりアセンブリを読んだりしながら解析していた
