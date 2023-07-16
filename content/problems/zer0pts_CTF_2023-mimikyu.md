+++
title = "zer0pts CTF 2023 - mimikyu"
date = 2023-07-16

[taxonomies]
tags = ["CTF", "Writeup", "rev"]
+++

## TL;DR

- ライブラリ関数のアドレス解決がベタ書きされている
- ついでに引数も与えて呼び出されている
- gdbで取得した関数ポインタをcallする場所にブレークポイントを設置しどの関数がどんな引数で呼び出されるかを確認する

## Writeup

x86_64のELFが与えられるが、問題文に次のような不穏な事が書いてある。

> Deja vu in Windows

実際にバイナリをGhidraで開いてみると次のようになっている(変数のリネームを行い、更にコメントを加えている)。

```c

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 main(int param_1,undefined8 *param_2)

{
  int iVar1;
  undefined8 uVar2;
  size_t sVar3;
  long hlibc;
  long hlibgmp;
  long in_FS_OFFSET;
  ulong i;
  ulong j;
  ulong k;
  undefined v1 [16];
  undefined v2 [16];
  undefined v3 [24];
  long local_10;
  char *inp;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (param_1 < 2) {
    printf("Usage: %s FLAG\n",*param_2);
    uVar2 = 1;
    goto LAB_00101d61;
  }
  inp = (char *)param_2[1];
  sVar3 = strlen(inp);
  if (sVar3 != 0x28) {
    puts("Nowhere near close.");
    uVar2 = 0;
    goto LAB_00101d61;
  }
  hlibc = LoadLibraryA("libc.so.6");
  if (hlibc == 0) {
                    /* WARNING: Subroutine does not return */
    __assert_fail("hLibc != NULL","main.c",0x4a,(char *)&__PRETTY_FUNCTION__.0);
  }
  hlibgmp = LoadLibraryA("libgmp.so");
  if (hlibgmp == 0) {
                    /* WARNING: Subroutine does not return */
    __assert_fail("hGMP != NULL","main.c",0x4c,(char *)&__PRETTY_FUNCTION__.0);
  }
  ResolveModuleFunction(hlibgmp,0x71b5428d,v1);
  ResolveModuleFunction(hlibgmp,0x71b5428d,v2);
  ResolveModuleFunction(hlibgmp,0x71b5428d,v3);
  ResolveModuleFunction(hlibc,0xfc7e7318,_main);
  ResolveModuleFunction(hlibc,0x9419a860,stdout,0);
  printf("Checking...");
  for (i = 0; i < 0x28; i = i + 1) {
                    /* isprint: printableかどうかを調べる */
    iVar1 = ResolveModuleFunction(hlibc,0x4e8a031a,(int)inp[i]);
    if (iVar1 == 0) goto LAB_00101ce7;
  }
  for (j = 0; j < 0x28; j = j + 4) {
    ResolveModuleFunction(hlibgmp,0xf122f362,v2,1);
    for (k = 0; k < 3; k = k + 1) {
      ResolveModuleFunction(hlibc,0xd588a9,0x2e);
      iVar1 = ResolveModuleFunction(hlibc,0x7b6cea5d);
      cap(hlibc,hlibgmp,(long)(iVar1 % 0x10000),v1);
      ResolveModuleFunction(hlibgmp,0x347d865b,v2,v2,v1);
    }
    ResolveModuleFunction(hlibc,0xd588a9,0x2e);
    iVar1 = ResolveModuleFunction(hlibc,0x7b6cea5d);
    cap(hlibc,hlibgmp,(long)(iVar1 % 0x10000),v3);
    ResolveModuleFunction(hlibgmp,0xf122f362,v1,*(undefined4 *)(inp + j));
                    /* v1 <- v1^v3 mod v2 */
    ResolveModuleFunction(hlibgmp,0x9023667e,v1,v1,v3,v2);
    iVar1 = ResolveModuleFunction(hlibgmp,0xb1f820dc,v1,*(undefined8 *)(encoded + (j >> 2) * 8));
    if (iVar1 != 0) goto LAB_00101ce7;
  }
  puts("\nCorrect!");
  goto LAB_00101cf6;
LAB_00101ce7:
  puts("\nWrong.");
LAB_00101cf6:
  ResolveModuleFunction(hlibgmp,0x31cc4f9f,v1);
  ResolveModuleFunction(hlibgmp,0x31cc4f9f,v2);
  ResolveModuleFunction(hlibgmp,0x31cc4f9f,v3);
  CloseHandle(hlibc);
  CloseHandle(hlibgmp);
  uVar2 = 0;
LAB_00101d61:
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar2;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}


```

not strippedであることに胸を撫で下ろしつつ、それはそれとして`ResolveModuleFunction`という触れたくないような名前の関数が存在している。Windows APIの`GetProcAddress`っぽさがあると感じながら、この関数のデコンパイル結果を見てみると次のようになっている。

```c

undefined8
ResolveModuleFunction
          (undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
          undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8,
          undefined8 param_9,int target_hash,undefined8 param_11,undefined8 param_12,
          undefined8 param_13,undefined8 param_14)

{
  int iVar1;
  char in_AL;
  int iVar2;
  int iVar3;
  long lVar4;
  undefined8 *puVar5;
  ulong uVar6;
  long in_FS_OFFSET;
  int local_160;
  int local_15c;
  int local_158;
  long local_150;
  long local_148;
  long local_140;
  undefined8 local_138;
  long *local_130;
  uint *local_128;
  long local_120;
  code *local_118;
  uint local_110;
  undefined4 local_10c;
  undefined8 *local_108;
  undefined *local_100;
  undefined8 local_f8 [7];
  long local_c0;
  undefined local_b8 [16];
  undefined8 local_a8;
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_90;
  undefined4 local_88;
  undefined4 local_78;
  undefined4 local_68;
  undefined4 local_58;
  undefined4 local_48;
  undefined4 local_38;
  undefined4 local_28;
  undefined4 local_18;
  
  if (in_AL != '\0') {
    local_88 = param_1;
    local_78 = param_2;
    local_68 = param_3;
    local_58 = param_4;
    local_48 = param_5;
    local_38 = param_6;
    local_28 = param_7;
    local_18 = param_8;
  }
  local_c0 = *(long *)(in_FS_OFFSET + 0x28);
  local_150 = 0;
  local_138 = 0;
  local_110 = 0x10;
  local_10c = 0x30;
  local_108 = (undefined8 *)&stack0x00000008;
  local_100 = local_b8;
  local_a8 = param_11;
  local_a0 = param_12;
  local_98 = param_13;
  local_90 = param_14;
  iVar2 = GetModuleInformation(param_9,&local_150);
  if (iVar2 == 0) {
                    /* WARNING: Subroutine does not return */
    __assert_fail("GetModuleInformation(hModule, &lpmodinfo)","obfuscate.h",0x71,
                  "ResolveModuleFunction");
  }
  for (local_130 = *(long **)(local_150 + 0x10); *local_130 != 0; local_130 = local_130 + 2) {
    lVar4 = *local_130;
    if (lVar4 == 0xb) {
      local_160 = (int)local_130[1];
    }
    else if (lVar4 < 0xc) {
      if (lVar4 == 5) {
        local_140 = local_130[1];
      }
      else if (lVar4 == 6) {
        local_148 = local_130[1];
      }
    }
  }
  dlerror();
  iVar1 = (int)local_148;
  iVar2 = (int)local_140;
  local_15c = 0;
  do {
    if ((iVar2 - iVar1) / local_160 <= local_15c) goto LAB_0010177e;
    local_128 = (uint *)(local_148 + (long)local_15c * 0x18);
    if ((*(byte *)(local_148 + (long)local_15c * 0x18 + 4) & 0xf) == 2) {
      local_120 = local_140 + (ulong)*local_128;
      iVar3 = CryptGetHashParam(local_120);
      if (target_hash == iVar3) {
        local_118 = (code *)dlsym(param_9,local_120);
        lVar4 = dlerror();
        if (lVar4 != 0) {
          do {
            invalidInstructionException();
          } while( true );
        }
        for (local_158 = 0; local_158 < 6; local_158 = local_158 + 1) {
          if (local_110 < 0x30) {
            uVar6 = (ulong)local_110;
            local_110 = local_110 + 8;
            puVar5 = (undefined8 *)(local_100 + uVar6);
          }
          else {
            puVar5 = local_108;
            local_108 = local_108 + 1;
          }
          local_f8[local_158] = *puVar5;
        }
        local_138 = (*local_118)(local_f8[0],local_f8[1],local_f8[2],local_f8[3],local_f8[4],
                                 local_f8[5]);
LAB_0010177e:
        if (local_c0 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
          __stack_chk_fail();
        }
        return local_138;
      }
    }
    local_15c = local_15c + 1;
  } while( true );
}


```

縦に長いが、重要な部分だけを抜粋すると次の通り

```c
      if (target_hash == iVar3) {
        local_118 = (code *)dlsym(param_9,local_120);
        lVar4 = dlerror();
        if (lVar4 != 0) {
          do {
            invalidInstructionException();
          } while( true );
        }
        for (local_158 = 0; local_158 < 6; local_158 = local_158 + 1) {
          if (local_110 < 0x30) {
            uVar6 = (ulong)local_110;
            local_110 = local_110 + 8;
            puVar5 = (undefined8 *)(local_100 + uVar6);
          }
          else {
            puVar5 = local_108;
            local_108 = local_108 + 1;
          }
          local_f8[local_158] = *puVar5;
        }
        local_138 = (*local_118)(local_f8[0],local_f8[1],local_f8[2],local_f8[3],local_f8[4],
                                 local_f8[5]);
LAB_0010177e:
        if (local_c0 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
          __stack_chk_fail();
        }
        return local_138;
      }
```

ライブラリ内の関数をハッシュ化して、第2引数に与えたハッシュと一致するものを引っ張って来て、関数の後続の引数に与えた引数を実行しているらしい。実行までしているため、`GetProcAddress`よりもやっていることは広い。

例えば`ResolveModuleFunction(hlibgmp,0x9023667e,v1,v1,v3,v2);`という呼び出しは`hlibgmp`内の関数の内、ハッシュ値が0x9023667eであるものを、引数`(v1, v1, v3, v2)`という形で呼び出すという事に対応する。

このハッシュを再現してどの関数が使われているのかを特定しても良かったのだが、面倒だったのでgdbで`local_138 = (*local_118)(local_f8[0],local_f8[1],local_f8[2],local_f8[3],local_f8[4],local_f8[5]);`に対応する命令にブレークポイントを設置し、どの関数が呼ばれているかを確認した。次のような感じで、どの関数がどんな引数で呼ばれているのかを確認出来る。

```txt
pwndbg> brva 0x1752
Breakpoint 2 at 0x555555555752
pwndbg> c
Continuing.

Breakpoint 2, 0x0000555555555752 in ResolveModuleFunction ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
*RAX  0x7fffffffdc10 —▸ 0x7ffff7fc1000 ◂— jg     0x7ffff7fc1047
 RBX  0x0
*RCX  0x0
*RDX  0x555555559330 ◂— 0x555555559
*RDI  0x7fffffffdc10 —▸ 0x7ffff7fc1000 ◂— jg     0x7ffff7fc1047
*RSI  0x0
*R8   0x7fffffffdd68 —▸ 0x7fffffffe007 ◂— '/home/xornet/CTF/zer0pts2023/mimikyu/mimikyu'
*R9   0x2f7fe4900
*R10  0x7ffff7d17c90 (__gmpz_init) ◂— endbr64 
*R11  0x0
 R12  0x7fffffffdd68 —▸ 0x7fffffffe007 ◂— '/home/xornet/CTF/zer0pts2023/mimikyu/mimikyu'
 R13  0x5555555558fe (main) ◂— endbr64 
 R14  0x555555557d78 (__do_global_dtors_aux_fini_array_entry) —▸ 0x555555555220 (__do_global_dtors_aux) ◂— endbr64 
 R15  0x7ffff7ffd040 (_rtld_global) —▸ 0x7ffff7ffe2e0 —▸ 0x555555554000 ◂— 0x10102464c457f
*RBP  0x7fffffffdbb0 —▸ 0x7fffffffdc50 ◂— 0x2
*RSP  0x7fffffffda40 ◂— 0x71b5428d00000000
*RIP  0x555555555752 (ResolveModuleFunction+785) ◂— call   r10
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x555555555752 <ResolveModuleFunction+785>    call   r10                           <__gmpz_init>
        rdi: 0x7fffffffdc10 —▸ 0x7ffff7fc1000 ◂— jg     0x7ffff7fc1047
        rsi: 0x0
        rdx: 0x555555559330 ◂— 0x555555559
        rcx: 0x0
 
   0x555555555755 <ResolveModuleFunction+788>    mov    qword ptr [rbp - 0x130], rax
   0x55555555575c <ResolveModuleFunction+795>    jmp    ResolveModuleFunction+829                <ResolveModuleFunction+829>
 
   0x55555555575e <ResolveModuleFunction+797>    add    dword ptr [rbp - 0x154], 1
   0x555555555765 <ResolveModuleFunction+804>    mov    eax, dword ptr [rbp - 0x14c]
   0x55555555576b <ResolveModuleFunction+810>    cdq    
   0x55555555576c <ResolveModuleFunction+811>    idiv   dword ptr [rbp - 0x158]
   0x555555555772 <ResolveModuleFunction+817>    cmp    dword ptr [rbp - 0x154], eax
   0x555555555778 <ResolveModuleFunction+823>    jl     ResolveModuleFunction+421                <ResolveModuleFunction+421>
 
   0x55555555577e <ResolveModuleFunction+829>    mov    rax, qword ptr [rbp - 0x130]
   0x555555555785 <ResolveModuleFunction+836>    mov    rdx, qword ptr [rbp - 0xb8]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffda40 ◂— 0x71b5428d00000000
01:0008│     0x7fffffffda48 —▸ 0x555555559c90 —▸ 0x7ffff7cfe000 ◂— 0x10102464c457f
02:0010│     0x7fffffffda50 ◂— 0xff000000
03:0018│     0x7fffffffda58 ◂— 0x4800000018
04:0020│     0x7fffffffda60 ◂— 0x3dc800000006
05:0028│     0x7fffffffda68 —▸ 0x555555559c90 —▸ 0x7ffff7cfe000 ◂— 0x10102464c457f
06:0030│     0x7fffffffda70 —▸ 0x7ffff7cff6c8 ◂— 0x0
07:0038│     0x7fffffffda78 —▸ 0x7ffff7d03490 ◂— 0x5f6e6f6d675f5f00
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► f 0   0x555555555752 ResolveModuleFunction+785
   f 1   0x555555555a25 main+295
   f 2   0x7ffff7dacd90 __libc_start_call_main+128
   f 3   0x7ffff7dace40 __libc_start_main+128
   f 4   0x5555555551a5 _start+37
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> 
```

ご丁寧にも`call r10`のところで`__gmpz_init`が呼ばれることが示されている。これと同様にしてmain関数で呼ばれている関数とそのハッシュを照合していくと次のようになる[^1]。

- 0x71b5428d: `__gmpz_init@gmp`
- 0xfc7e7318: `srandom@libc`
- 0x9419a860: `setbuf@libc`
- 0x4e8a031a: `isprint@libc`
- 0xf122f362: `__gmpz_set_ui@gmp`
- 0xd588a9: `putchar@libc`
- 0x7b6cea5d: `rand@libc`
- 0xe75e0ffe: `hcreate@libc`
- 0x1c46d38a: `memfrob@libc`
- 0x7489af98: `__gmp_sprintf@gmp`
- 0xed3b7a10: `__gmpz_add_ui@gmp`
- 0x50ab4097: `hsearch@libc`
- 0xaf4c09bd: `hdestroy@libc`
- 0x1c3ef940: `__gmpz_sub_ui@gmp`
- 0x347d865b: `__gmpz_mul@gmp`
- 0x9023667e: `__gmpz_powm@gmp`
- 0xb1f820dc: `__gmpz_cmp_ui@gmp`

これを元にしてバイナリを読んでいくと重要なのはフラグを4バイトずつに区切って色々やっているfor文中の次の2行になる。

```c
    ResolveModuleFunction(hlibgmp,0x9023667e,v1,v1,v3,v2);
    iVar1 = ResolveModuleFunction(hlibgmp,0xb1f820dc,v1,*(undefined8 *)(encoded + (j >> 2) * 8));
```

これは`v1 = pow(v1, v3, v2)`をした後に、グローバル変数`encoded`に存在する対応した数値と比較するという形になっている。`v1`はフラグを4バイトずつ区切って数値と見なした時の値であるが、`v2`と`v3`は`rand`を使って引っ張ってきているようで再現等で求めるのはできればやりたくない。結局、`ResolveModuleFunction(hlibgmp,0x9023667e,v1,v1,v3,v2);`にブレークポイントを張って、`v2`と`v3`を読むという方針をとった。

値を覗くと、`v2`が3つの素数の合成数から構成されており、RSAの暗号化をしているようである。しかも各素数の大きさは0x10000未満っぽいのでfactordbやSageMathに放り込んだ結果を用いれば簡単に復号出来る。

## Code

```python
from xcrypto.prime import factorize_by_factordb
from tqdm import tqdm


mods = [[38830568246783, 25997, 31567, 47317], [55875622227251, 23719, 36493, 64553], [3875886538523, 4967, 12197, 63977], [18342125763727, 18481, 20011, 49597], [10828735575677, 3671, 53861, 54767], [32860319419313, 21277, 23789, 64921], [17866096656883, 14797, 25577, 47207], [1211339173321, 3779, 11149, 28751], [0x00005f8d20bddf39], [0x000045b14e11e0ed]]

# tooooooo lazy
for m in tqdm(mods):
    if len(m) == 1:
        res = factorize_by_factordb(m[0])
        for x, e in res:
            assert e == 1
            m.append(x)

print(mods)

es = [0xf0d3, 0x85f, 0x8e63, 0x8249, 0xc6a1, 0xc6d, 0xaef5, 0xd5df, 0xe68d, 0xf3fb]

encoded = b'\xf4\xc5\x25\xc0\xe4\x0f\x00\x00\x8a\x7e\xf1\x2f\x79\x1b\x00\x00\x40\xab\x56\xb1\x83\x01\x00\x00\xda\xe5\xf5\xfc\xef\x0b\x00\x00\x51\xe2\x86\xcf\x97\x02\x00\x00\xb4\xd4\xc1\xed\xb3\x0e\x00\x00\x08\x3a\xce\x10\xfa\x00\x00\x00\x72\x86\x41\xdd\x2b\x00\x00\x00\x46\xea\x50\x50\xbb\x5e\x00\x00\x86\xcf\x73\x9b\xbf\x05\x00\x00'

xs = [int.from_bytes(encoded[i:i+8], "little") for i in range(0, len(encoded), 8)]

flag = b""
for mod, e, x in zip(mods, es, xs):
    m, p1, p2, p3 = mod
    assert m == p1*p2*p3

    phi = (p1 - 1) * (p2 - 1) * (p3 - 1)
    d = pow(e, -1, phi)
    pt = pow(x, d, m).to_bytes(4, "little")
    flag += pt
    print(flag)
```

- `xcrypto.prime.factorize_by_factordb`は与えた数をfactordbに突っ込んで素因数分解結果を返してくれるやつ

## Flag

- `zer0pts{L00k_th3_1nt3rn4l_0f_l1br4r13s!}`

---

[^1]: gdbスクリプトを用いて自動化するのが正しいと思うが、その手間をサボって全部手動でやった。ちなみにRSAの復号パートも同様
