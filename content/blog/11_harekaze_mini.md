+++
title = "Writeup: Harekaze mini CTF 2020"
date = 2020-12-27

[taxonomies]
tags = ["CTF", "Writeup", "Rev", "Crypto"]
+++

この土日に開催されていたHarekaze mini CTF 2020に出たのでWriteupを書きます。扱うのは次の5問です。

<!-- more -->

- [Rev] Easy Flag Checker
- [Rev] wait
- [Rev] Tiny Flag Checker
- [Crypto] rsa
- [Crypto] Wilhelmina says

運営提供のリポジトリ: <https://github.com/TeamHarekaze/harekaze-mini-ctf-2020-challenges-public>

## [Rev] Easy Flag Checker

典型的なCrackMe問題。Ghidraに投げると次のようなデコンパイル結果が返ってくる

```C
undefined8 check(char *input,char *target)

{
  char cVar1;
  int local_c;
  
  local_c = 0;
  while( true ) {
    if (0x22 < local_c) {
      return 0;
    }
    cVar1 = (*(code *)funcs[local_c % 3])
                      ((ulong)(uint)(int)target[local_c],(ulong)(uint)(int)(char)table[local_c],
                       (ulong)(uint)(int)(char)table[local_c]);
    if (cVar1 < input[local_c]) break;
    if (input[local_c] < cVar1) {
      return 0xffffffff;
    }
    local_c = local_c + 1;
  }
  return 1;
}

```

main関数は入力を処理して`check`に投げるだけなので割愛。注目すべきは`*(code *)funcs[local_c % 3]`の部分でここでインデックスを3で割った余り毎にどの関数を使うか指定している。`funcs`を見に行くとインデックスを3で割った余り: 0, 1, 2に対してそれぞれadd, sub, xorが該当するのでインデックスに対応して逆算するコードを書いた。

```python
from xcrypto.result import Result


def exploit():
    table = [
        0xE2, 0x00, 0x19, 0x00, 0xFB, 0x0D, 0x19, 0x02, 0x38, 0xE0, 0x22, 0x12, 0xBD, 0xED, 0x1D, 0xF5,
        0x2F, 0x0A, 0xC1, 0xFC, 0x00, 0xF2, 0xFC, 0x51, 0x08, 0x13, 0x06, 0x07, 0x39, 0x3C, 0x05, 0x39,
        0x13, 0xBA, 0x00
    ]
    target = "fakeflag{this_is_not_the_real_flag}"
    funcs = [
        lambda x, y: x + y,
        lambda x, y: x - y,
        lambda x, y: x ^ y
    ]

    flag = ""
    for i, c in enumerate(target):
        flag += chr(funcs[i%3](ord(c), table[i]) & 0xff)

    return Result(flag)


if __name__ == "__main__":
    res = exploit()
    if res.isSuccess():
        print(res.unwrap())

```

余談ですが[LazyGhidra](https://github.com/AllsafeCyberSecurity/LazyGhidra)というスクリプトを使うと上記コードの`table`みたいにバイト列を選択して良い感じに抽出してPythonやCで扱えるようにしてくれます。

- Flag: `HarekazeCTF{0rth0d0x_fl4g_ch3ck3r!}`

## [Rev] Wait

これまたCrackMe、しかもフラグのフォーマットは`^HarekazeCTF\\{ID[A-Z]{4}X\\}$`なので{{katex(body="26^{4}=456976")}}回の試行で済む...と思いきや後述する罠がある。

デコンパイル結果全体が長いのでGhidraの結果は割愛するが、入力毎に`system("sleep 3.00")`が実行してから入力のチェックをしているため愚直に総当りすると最大で約137万秒、つまり16日ぐらいかかる計算になる。なおこのCTFは24時間しか開催されない。

この`sleep 3.00`だが次のようなコードで構成されている。

```C
while (local_d4 < 0xb) {
    local_b8[local_d4] = local_b8[local_d4] + command1[local_d4];
    local_d4 = local_d4 + 1;
}
```

`local_b8`は事前に定義された文字列であり、`command1`で各インデックス毎に加算を施している。ということは`command1`を書き換えて別の瞬殺されるコマンドに変えればこの処理をバイパス出来そうである...と思いきや出来ない。次のコードで`system`に渡す文字列が`sleep 3.00`であるかをチェックしている。

```C
SHA1(local_b8,0xb,local_98);
local_d0 = 0;
while (local_d0 < 0xb) {
    if (local_98[local_d0] != local_58[local_d0]) {
        puts("Be patient");
        goto LAB_00400b0c;
    }
    local_d0 = local_d0 + 1;
}
```

`local_b8`文字列のSHA1ハッシュを`local_98`に格納し、`local_58`と照合することでこの文字列の書き換えを防いでいる。

というわけで実行コマンドの変更は難しい、そこで`call system`自体を書き換える。この付近のディスアセンブル結果は次の通り

```
                             LAB_00400a6a                                    XREF[1]:     00400a2c(j)  
        00400a6a 83 bd 38        CMP        dword ptr [RBP + local_d0],0xa
        00400a71 7e bb           JLE        LAB_00400a2e
        00400a73 48 8d 85        LEA        RAX=>local_b8,[RBP + -0xb0]
        00400a7a 48 89 c7        MOV        RDI,RAX
        00400a7d e8 9e fb        CALL       system                                           int system(char * __command)
        00400a82 85 c0           TEST       EAX,EAX
        00400a84 74 11           JZ         LAB_00400a97
        00400a86 bf 08 0c        MOV        EDI=>s_Be_patient_00400c08,s_Be_patient_00400c08 = "Be patient"
        00400a8b e8 70 fb        CALL       puts                                             int puts(char * __s)
        00400a90 b8 00 00        MOV        EAX,0x0
        00400a95 eb 75           JMP        LAB_00400b0c

```

`call system`後に`test eax, eax`で`eax`が0であるかをチェックしている。そこで`xor eax, eax; nop; nop; nop`に書き換えて(`nop`はバイト数をあわせる為)`system`を呼ばずにフラグチェックへ行くことが出来る。Ghidraだとpatch後に抽出したバイナリが実行時エラーになったので命令だけ参考にして、書き換えにはstirlingという太古のバイナリエディタを使いました。

あとはPythonのSubprocessを使って総当りする。使用したコードは次の通り。

```Python
from xcrypto.result import Result
from hashlib import sha1
from string import ascii_uppercase
from subprocess import PIPE
import subprocess


# challenge info
target = b"\x1f\xcc\xe7\xec\x44\xbe\xb7\x2c\x99\x4e\x2c\xd6\x9c\x46\x29\x16\xca\x8e\xc8\x10"


# sleep 3.00
def get_cmd():
    command1 = [
        0x4D, 0x28, 0x46, 0x4F, 0x65, 0x15, 0x17, 0x0D, 0x13, 0x10
    ]
    commandl2 = b"&D\x1f\x16\x0b\x0b\x1c!\x1d "

    cmd = ""
    for i in range(len(command1)):
        cmd += chr(command1[i] + commandl2[i])

    print(sha1((cmd + "SALT").encode()).hexdigest())
    return cmd


def exploit():
    for c1 in ascii_uppercase:
        print("[+] attempting:", c1)
        for c2 in ascii_uppercase:
            for c3 in ascii_uppercase:
                for c4 in ascii_uppercase:
                    msg = "HarekazeCTF{ID" + c1 + c2 + c3 + c4 + "X}"
                    p = subprocess.run("./a_edit_4.out", input=msg.encode()+b"\n", stdout=PIPE)
                    res = p.stdout
                    if b"Correct" in res:
                        return Result(msg)

    return Result(None, False)


if __name__ == "__main__":
    res = exploit()
    if res.isSuccess():
        print(res.unwrap())

```

- Flag: `HarekazeCTF{IDRACIX}`

## [Rev] Tiny Flag Checker

これもCrackme、しかし何故か手元の環境(WSL1)で実行出来なかったのでファイルを調べてみる。

```
$ file tiny
tiny: ELF, unknown class 85
```

ELFであることは分かったが普通のELFでは無さそうである。hexdumpしてみると次のようになる。

```
$ hexdump -C tiny
00000000  7f 45 4c 46 55 55 4e 5f  4b 41 57 41 49 49 16 c6  |.ELFUUN_KAWAII..|
00000010  02 00 3e 00 41 42 43 44  a2 00 40 00 00 00 00 00  |..>.ABCD..@.....|
00000020  40 00 00 00 00 00 00 00  e7 fc 63 75 63 cf fd f0  |@.........cuc...|
00000030  66 ae dc 4f 4f cf 38 00  01 00 00 00 00 00 00 00  |f..OO.8.........|
00000040  01 00 00 00 05 00 00 00  00 00 00 00 00 00 00 00  |................|
00000050  00 00 40 00 00 00 00 00  4e 6f 70 65 2e 2e 2e 0a  |..@.....Nope....|
00000060  6e 01 00 00 00 00 00 00  6e 01 00 00 00 00 00 00  |n.......n.......|
00000070  49 6e 70 75 74 3a 20 00  43 6f 72 72 65 63 74 21  |Input: .Correct!|
00000080  20 46 6c 61 67 3a 20 48  61 72 65 6b 61 7a 65 43  | Flag: HarekazeC|
00000090  54 46 7b 7d 0a b8 01 00  00 00 bf 01 00 00 00 0f  |TF{}............|
000000a0  05 c3 48 83 ec 10 49 89  e0 48 83 ec 10 49 89 e1  |..H...I..H...I..|
000000b0  66 0f ef c0 0f 29 04 24  0f 29 44 24 10 be 70 00  |f....).$.)D$..p.|
000000c0  40 00 ba 07 00 00 00 e8  c9 ff ff ff 31 c0 31 ff  |@...........1.1.|
000000d0  4c 89 c6 ba 10 00 00 00  0f 05 49 8b 00 49 31 01  |L.........I..I1.|
000000e0  49 8b 40 08 49 31 41 08  49 c1 09 29 49 c1 49 08  |I.@.I1A.I..)I.I.|
000000f0  13 48 8b 04 25 00 00 40  00 49 31 01 48 8b 04 25  |.H..%..@.I1.H..%|
00000100  08 00 40 00 49 31 41 08  48 8b 04 25 28 00 40 00  |..@.I1A.H..%(.@.|
00000110  49 33 01 48 8b 14 25 30  00 40 00 49 33 51 08 48  |I3.H..%0.@.I3Q.H|
00000120  21 c0 75 32 48 39 d0 75  2d be 78 00 40 00 ba 1b  |!.u2H9.u-.x.@...|
00000130  00 00 00 e8 5d ff ff ff  4c 89 c6 ba 10 00 00 00  |....]...L.......|
00000140  e8 50 ff ff ff be 93 00  40 00 ba 02 00 00 00 e8  |.P......@.......|
00000150  41 ff ff ff eb 0f be 58  00 40 00 ba 08 00 00 00  |A......X.@......|
00000160  e8 30 ff ff ff b8 3c 00  00 00 31 ff 0f 05        |.0....<...1...|
```

ヘッダに`UUN_KAWAII`が発生している。このせいでGhidraに放り込んでも上手く認識してくれなかったので`UUN`を`02 01 01`に書き換えて`e_ident`として問題無い値にしてから読み込んだらGhidraで無事に読めた。

- 参考: <https://linuxjm.osdn.jp/html/LDP_man-pages/man5/elf.5.html>

すると次のようなentryのディスアセンブル結果が得られる。

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined entry()
             undefined         AL:1           <RETURN>
                             entry                                           XREF[2]:     Entry Point(*), 00400018(*)  
        004000a2 48 83 ec 10     SUB        RSP,0x10
        004000a6 49 89 e0        MOV        R8,RSP
        004000a9 48 83 ec 10     SUB        RSP,0x10
        004000ad 49 89 e1        MOV        R9,RSP
        004000b0 66 0f ef c0     PXOR       XMM0,XMM0
        004000b4 0f 29 04 24     MOVAPS     xmmword ptr [RSP],XMM0
        004000b8 0f 29 44        MOVAPS     xmmword ptr [RSP + 0x10],XMM0
        004000bd be 70 00        MOV        ESI=>Elf64_Phdr_ARRAY_00400040[0].p_align,Elf6   = null
        004000c2 ba 07 00        MOV        EDX,0x7
        004000c7 e8 c9 ff        CALL       FUN_00400095                                     undefined FUN_00400095()
        004000cc 31 c0           XOR        EAX,EAX
        004000ce 31 ff           XOR        EDI,EDI
        004000d0 4c 89 c6        MOV        RSI,R8
        004000d3 ba 10 00        MOV        EDX,0x10
        004000d8 0f 05           SYSCALL
        004000da 49 8b 00        MOV        RAX,qword ptr [R8]
        004000dd 49 31 01        XOR        qword ptr [R9],RAX
        004000e0 49 8b 40 08     MOV        RAX,qword ptr [R8 + 0x8]
        004000e4 49 31 41 08     XOR        qword ptr [R9 + 0x8],RAX
        004000e8 49 c1 09 29     ROR        qword ptr [R9],0x29
        004000ec 49 c1 49        ROR        qword ptr [R9 + 0x8],0x13
        004000f1 48 8b 04        MOV        RAX,qword ptr [Elf64_Ehdr_00400000]              = 
        004000f9 49 31 01        XOR        qword ptr [R9],RAX
        004000fc 48 8b 04        MOV        RAX,qword ptr [Elf64_Ehdr_00400000.e_ident_pad   = null
        00400104 49 31 41 08     XOR        qword ptr [R9 + 0x8],RAX
        00400108 48 8b 04        MOV        RAX,qword ptr [Elf64_Ehdr_00400000.e_shoff]      = null
        00400110 49 33 01        XOR        RAX,qword ptr [R9]
        00400113 48 8b 14        MOV        RDX,qword ptr [Elf64_Ehdr_00400000.e_flags]      = null
        0040011b 49 33 51 08     XOR        RDX,qword ptr [R9 + 0x8]
        0040011f 48 21 c0        AND        RAX,RAX
        00400122 75 32           JNZ        LAB_00400156
        00400124 48 39 d0        CMP        RAX,RDX
        00400127 75 2d           JNZ        LAB_00400156
        00400129 be 78 00        MOV        ESI=>DAT_00400078,DAT_00400078                   = 43h    C
        0040012e ba 1b 00        MOV        EDX,0x1b
        00400133 e8 5d ff        CALL       FUN_00400095                                     undefined FUN_00400095()
        00400138 4c 89 c6        MOV        RSI,R8
        0040013b ba 10 00        MOV        EDX,0x10
        00400140 e8 50 ff        CALL       FUN_00400095                                     undefined FUN_00400095()
        00400145 be 93 00        MOV        ESI=>DAT_00400093,DAT_00400093                   = 7Dh    }
        0040014a ba 02 00        MOV        EDX,0x2
        0040014f e8 41 ff        CALL       FUN_00400095                                     undefined FUN_00400095()
        00400154 eb 0f           JMP        LAB_00400165
                             LAB_00400156                                    XREF[2]:     00400122(j), 00400127(j)  
        00400156 be 58 00        MOV        ESI=>Elf64_Phdr_ARRAY_00400040[0].p_paddr,Elf6   = null
        0040015b ba 08 00        MOV        EDX,0x8
        00400160 e8 30 ff        CALL       FUN_00400095                                     undefined FUN_00400095()
                             LAB_00400165                                    XREF[1]:     00400154(j)  
        00400165 b8 3c 00        MOV        EAX,0x3c
        0040016a 31 ff           XOR        EDI,EDI
        0040016c 0f 05           SYSCALL

```

これを頑張って読むと16文字フラグを読み込んで前半と後半に分割する。そしてそれぞれ右回転シフトを29bit, 17bitで施してから、ELFヘッダ中の値とXORしてその結果をELFヘッダ中の値と一致しているかを確認している。

というわけでこれを逆変換するコードを書けば良い。先程`UUN_KAWAII`の`UUN`の部分を書き換えてしまったのでそれを元に戻してから元に戻す

```Python
from xcrypto.result import Result
from pwn import p64


def exploit():
    f1 = 0xf0fdcf637563fce7 ^ 0x5f4e5555464c457f
    f2 = 0x38cf4f4fdcae66 ^ 0xc61649494157414b

    f1 = (f1 << 0x29) & 0xffffffffffffffff | f1 >> 0x17
    f2 = (f2 << 0x13) & 0xffffffffffffffff | f2 >> 0x2d

    flag = b""
    flag += p64(f1) + p64(f2)

    return Result(flag)


if __name__ == "__main__":
    res = exploit()
    if res.isSuccess():
        print(res.unwrap())

```

- Flag: `HarekazeCTF{fl4g_1s_t1ny_t00}`

## [Crypto] rsa

次のような暗号化スクリプトをくれる

```Python
from Crypto.Util.number import getStrongPrime, getRandomRange

with open("flag", "rb") as f:
  flag = int.from_bytes(f.read(), "big")

p = getStrongPrime(512)
q = getStrongPrime(512)
n = p * q
phi = (p-1)*(q-1)
e = 65537
c1 = pow(flag, e, n)
c2 = pow(p + q, e, n)
c3 = pow(p - q, e, n)

print(f"{n=}")
print(f"{e=}")
print(f"{c1=}")
print(f"{c2=}")
print(f"{c3=}")


```

通常のRSAで公開される値に加えて{{katex(body="N=pq")}}における{{katex(body="p, q")}}を使い、{{katex(body="N")}}を法として{{katex(body="(p+q)^e, (p-q)^e")}}もくれる。

これは二項定理よりそれぞれ{{katex(body="p^{65537} + q^{65537}, p^{65537} - q^{65537}")}}になる。したがってこの2つを足して{{katex(body="N")}}を法とした2の逆数を掛けると{{katex(body="p^{65537}")}}が手に入る。

後は(自分の記事で申し訳ないですが)[この記事](https://project-euphoria.dev/blog/8-gcd-for-crypto/)の真ん中の問題と同様に、{{katex(body="p")}}の倍数を{{katex(body="p")}}の倍数で割った余りも{{katex(body="p")}}の倍数となる事を利用し、最大公約数から{{katex(body="p")}}を抽出することが出来る。

```Python
from xcrypto.result import Result
from math import gcd
from xcrypto.rsa import dec_pq
from Crypto.Util.number import long_to_bytes


def exploit():
    n = 133957491909745071464818932891535809774039075882486614948793786706389844163167535932401761676665761652470189326864929940531781069869721371517782821535706577114286987515166157005227505921885357696815641758531922874502352782124743577760141307924730988128098174961618373787528649748605481871055458498670887761203
    e = 65537
    c1 = 35405298533157007859395141814145254094484385088710533905385734792407576252003080929963085838327711405177354982539867453717921912839308282313390558033140654288445877937672625603540090399691469218188262950682485682814224928528948502206046863184746747265896306678488587444125143233443450049838709221084210200357
    c2 = 23394879596667385465597018769822552384439114548016006879565586102300995936951562766011707923675690015217418498865916391314367448706185724546566348496812451258316472754407976794025546555423254676274654957362894171995220230464953432393865332807738040967281350952790472772600745096787761443699676372681208295288
    c3 = 54869102748428770635192859184579301467475982074831093316564134451063250935340131274147041633101346896954483059058671502582914428555153910133076778016989842641074276293354765141522703887273042367333036465503084165682591308676428523152462442280924054400997210800504726635778588407034149919869556306659386868798

    p_65537 = c2 + c3
    p = gcd(n, p_65537)
    flag = long_to_bytes(dec_pq(c1, p, n // p, e))

    return Result(flag)

if __name__ == "__main__":
    res = exploit()
    if res.isSuccess():
        print(res.unwrap())

```

- Flag: `HarekazeCTF{RSA_m34n5_Rin_Shiretoko_Ango}`

## [Crypto] Wilhelmina says

次のような暗号化スクリプトをくれる

```Python
from Crypto.Util.number import getStrongPrime
import random

p = getStrongPrime(512)

with open("flag", "rb") as f:
  flag = int.from_bytes(f.read().strip(), "big")
  assert flag < p

t = flag.bit_length()
n = 5
k = 350

xs = [random.randint(2, p-1) for _ in range(n)]
ys = [x * flag % p for x in xs]
zs = [(y >> k) << k for y in ys]

print(f"{t=}")
print(f"{p=}")
print(f"{xs=}")
print(f"{zs=}")

```

`xs`の各要素`x`に対して`x * flag`を`p`で割ったもののMSBを複数くれる。ここから共通の係数である`flag`を求める問題はHidden Number Problemと呼ばれ、解が小さいなら格子基底縮小で解ける可能性がある。

まず、次のように{{katex(body="y_i")}}を既知部分{{katex(body="z_i")}}と未知部分{{katex(body="y_i'")}}に分割する

$$
y_i = z_i + y_i'
$$

この上で{{katex(body="y_i \equiv x_i \cdot \mathrm{flag} \bmod p")}}を利用し、合同式を外して整理すると、ある整数{{katex(body="l_i")}}を利用して

$$
y_i' = l_i p + x_i \cdot \mathrm{flag} - z_i
$$

が成り立つ。ここで次のような格子を用意する。

$$
L = \left(
        \begin{array}{ccccc}
            p & & & x_0 & -z_0 \cr & \ddots & & \vdots & \vdots \cr & & p & x_4 & -z_4 \cr & & & 2^{|x_i|-|\mathrm{flag}|} & \cr & & & & 2^{|x_i|}
        \end{array}
    \right)
$$

ここで{{katex(body="|x_i|, |\mathrm{flag}|")}}はそれぞれ{{katex(body="x_i")}}の平均bit数と{{katex(body="\mathrm{flag}")}}のbit数である。

これに右から{{katex(body="A = (l_0, \dots, l_4, \mathrm{flag}, 1)^{\mathrm{T}}")}}を掛けると{{katex(body="B = LA = (y_0', \dots, y_4',  2^{|x_i|-|\mathrm{flag}|} \cdot flag, 2^{|x_i|})^{\mathrm{T}}")}}が現れる。このベクトルは{{katex(body="L")}}の基底に比べてサイズが小さいのでLLLをしたら上手く現れてくれることが期待出来る。{{katex(body="B")}}から{{katex(body="y_i")}}を復元してその結果からフラグが導かれる。

(書いてて思ったけどこれ{{katex(body="B")}}の第3成分(0-origin)を係数で割れば出てくるじゃん...)

Sagemathを使って解いた↓

```Python
from Crypto.Util.number import long_to_bytes

flag_size = 311
p=10701453001723144480344017475825280248565900288828152690457881444597242894870175164568287850873496224666625464545640813032441546675898034617104256657175267
xs=[7891715755203660117196369138472423229419020799191062958462005957463124286065649164907374481781616021913252775381280072995656653443562728864428126093569737, 9961822260223825094912294780924343607768701240693646876708240325173173602886703232031542013590849453155723572635788526544113459131922826531325041302264965, 7554718666604482801859172289797064180343475598227680083039693492470379257725537783866346225587960481867556270277348918476304196755680361942599070096169454, 5460028735981422173260270143720425600672799255277275131842637821512408249661961734712595647644410959201308881934659222154413079105304697473190038457627041, 8621985577188280037674685081403657940857632446535799029971852830016634247561494048833624108644207879293891655636627384416153576622892618587617669199231771]
zs=[2445678981428533875266395719064486897322607935804981139297064047499983860197487043744531294747013763946234499465983314356438694756078915278742591478169600, 6687262023290381303903301700938596216218657180198116459210103464914665663217490218525920847803014050091904359944827298080739698457116239163607201903280128, 9144515139738671257281335253441395780954695458291758900110092599410878434836587336752247733779617485272269820837813132894795262162555273673307500761317376, 7005359236736263649027110410188576532095684249796929034336135801107965605961711614006159825405033239188458945408990893269975105260656611838449490684018688, 4638291797440604671051855904609667375394026160401800326727058461541969151082727684535417653507524951373254537356784859777006179731400955193335900924805120]
y_size = 350

c_1 = 2**(y_size - flag_size)
c_2 = 2**y_size

m_size  = 5 + 2
m_list = [
    [0 for _ in range(m_size)] for _ in range(m_size)
]

m_list[5][5] = c_1
m_list[6][6] = c_2

for i in range(5):
    m_list[i][i] = p
    m_list[5][i] = xs[i]
    m_list[6][i] = -zs[i]
    
m = Matrix(m_list)
llled = m.LLL()

for b in llled:
    for i in range(5):
        y = zs[i] + b[i]
        inv_x = inverse_mod(xs[i], p)
        flag = y*inv_x % p
        print(long_to_bytes(flag))
```

- Flag: `HarekazeCTF{H0chmu7_k0mm7_v0r_d3m_F411}`

## 感想

11月からほぼ毎週のように重いCTFに出ていたので(卒論執筆もあるし)年末ぐらいはCTF休もうと思っていたのですが、昨日の夕方ぐらいにチームDiscordでチャンネルが生えていたので参加しました。

どの問題も面白く、特に久しぶりに解ける難易度のRevが来て大いに楽しめました。

Cryptoはかなり歯ごたえがありました。Curving Torpedoは時間と脳味噌の都合でチームメイトに投げましたがパラメータの特定と離散対数問題を解く二段構えで「やるだけ」を回避しているのを感じました。

チームメイトに解法を聞いただけですが、楕円曲線の点から元の曲線を復元する問題は色々なパターンがあって面白いのでそのうちこのブログで取り上げるかもしれません。

このような楽しいCTFを開催してくださったHarekazeの皆様、ありがとうございました
