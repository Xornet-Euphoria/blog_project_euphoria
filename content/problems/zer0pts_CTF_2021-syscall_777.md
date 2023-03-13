+++
title = "zer0pts CTF 2021 - syscall 777"
date = 2023-03-13

[taxonomies]
tags = ["CTF", "Writeup", "rev", "BPF"]
+++

- 問題ファイル: [zer0pts-CTF-2021/reversing/syscall_777/distfiles at master · zer0pts/zer0pts-CTF-2021](https://github.com/zer0pts/zer0pts-CTF-2021/tree/master/reversing/syscall_777/distfiles)

## TL;DR

- 独自のシステムコール(777)が実装されているバイナリが与えられる
- これはseccompを用いて実装され、フラグチェッカーとなっている
- seccomp-toolsを使って中身を読み、条件を満たすフラグをz3に解かせる

## Prerequisite

- seccomp

## Writeup

x86_64のバイナリが配布される。とりあえずGhidraにぶち込むとmain関数の主要な処理は次のようになっている。

```c
  iVar1 = __isoc99_scanf(&DAT_0010116f,local_68);
  if (iVar1 == 1) {
    i = 1;
    do {
      iVar4 = (int)i;
      syscall(0x309,(ulong)local_68[i + -1],(ulong)local_68[iVar4 % 0xe],
              (ulong)local_68[(iVar4 + 1) % 0xe],(ulong)local_68[(iVar4 + 2) % 0xe]);
      piVar2 = __errno_location();
      iVar4 = *piVar2;
      if (iVar4 == 1) {
        puts("Wrong...");
        goto LAB_0010091f;
      }
      i = i + 1;
    } while (i != 0xf);
    iVar4 = 0;
    puts("Correct!");
  }
```

`ulong`でキャストされているので4バイトずつ値を見ながら`syscall`という関数[^1]に放り込まれているようである。注目すべきは番号で、この問題の名前からもわかるように777で呼ばれているが、通常こんな番号のシステムコールは存在しない。

独自のシステムコールの実装をどうしているのか全く見当がつかなかったが、straceでバイナリを走らせると次のような興味深い部分が見つかる(`-ik`オプションを付けており、`-i`はRIPを、`-k`はスタックトレースを表示する)。

```txt
[00007fea044c8d3e] prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) = 0
 > /usr/lib/x86_64-linux-gnu/libc-2.31.so(prctl+0xe) [0x11fd3e]
 > /home/xornet/CTF/2021/zer0pts-ctf-2021/reversing/syscall_777/distfiles/chall() [0x7f0]
 > /home/xornet/CTF/2021/zer0pts-ctf-2021/reversing/syscall_777/distfiles/chall() [0xaad]
 > /usr/lib/x86_64-linux-gnu/libc-2.31.so(__libc_start_main+0x80) [0x24010]
 > /home/xornet/CTF/2021/zer0pts-ctf-2021/reversing/syscall_777/distfiles/chall() [0x97a]
[00007fea044c8d3e] prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, {len=205, filter=0x7fff42301530}) = 0
 > /usr/lib/x86_64-linux-gnu/libc-2.31.so(prctl+0xe) [0x11fd3e]
 > /home/xornet/CTF/2021/zer0pts-ctf-2021/reversing/syscall_777/distfiles/chall() [0x835]
 > /home/xornet/CTF/2021/zer0pts-ctf-2021/reversing/syscall_777/distfiles/chall() [0xaad]
 > /usr/lib/x86_64-linux-gnu/libc-2.31.so(__libc_start_main+0x80) [0x24010]
 > /home/xornet/CTF/2021/zer0pts-ctf-2021/reversing/syscall_777/distfiles/chall() [0x97a]
```

seccompと言えば主にPwn問題で見られるシステムコールを許可したり禁止したりする機構であるが、ここでそれが使われているようである。スタックトレースを元にこれらが呼ばれている関数を探るとオフセットが`7c0`の部分に次のような関数が見つかる(デコンパイル結果は一部のみ抜粋)。

```c
  iVar1 = prctl(0x26,1,0,0,0);
  if (iVar1 == 0) {
    local_680 = local_678;
    local_688[0] = 0xcd;
    puVar3 = &DAT_00100b00;
    puVar4 = local_678;
    for (lVar2 = 0x19a; lVar2 != 0; lVar2 = lVar2 + -1) {
      *puVar4 = *puVar3;
      puVar3 = puVar3 + (ulong)bVar5 * -2 + 1;
      puVar4 = puVar4 + (ulong)bVar5 * -2 + 1;
    }
    iVar1 = prctl(0x16,2,local_688);
    if (iVar1 == 0) {
      if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return;
    }
  }
```

`DAT_00100b00`から値のコピーが行われその結果が`prctl`に渡されているようである。[Man page of PRCTL](https://linuxjm.osdn.jp/html/LDP_man-pages/man2/prctl.2.html)を見ると、BPFを使ってどんなシステムコールを許可/禁止するような処理を指定するようである。そういえばseccompが有効なバイナリに対する解析ツールに[david942j/seccomp-tools: Provide powerful tools for seccomp analysis](https://github.com/david942j/seccomp-tools)があった事を思い出したので、これでどうなっているのかを覗いてみると次が得られる。

```txt
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x15 0x00 0xc8 0x00000309  if (A != 0x309) goto 0202
 0002: 0x20 0x00 0x00 0x00000010  A = args[0]
 0003: 0x54 0x00 0x00 0x000000ff  A &= 0xff
 0004: 0x35 0xc7 0x00 0x00000080  if (A >= 128) goto 0204
 0005: 0x20 0x00 0x00 0x00000010  A = args[0]
 0006: 0x74 0x00 0x00 0x00000008  A >>= 8
 0007: 0x54 0x00 0x00 0x000000ff  A &= 0xff
 0008: 0x35 0xc3 0x00 0x00000080  if (A >= 128) goto 0204
 0009: 0x20 0x00 0x00 0x00000010  A = args[0]
 0010: 0x74 0x00 0x00 0x00000010  A >>= 16
 0011: 0x54 0x00 0x00 0x000000ff  A &= 0xff
 0012: 0x35 0xbf 0x00 0x00000080  if (A >= 128) goto 0204
 0013: 0x20 0x00 0x00 0x00000010  A = args[0]
 0014: 0x74 0x00 0x00 0x00000018  A >>= 24
 0015: 0x54 0x00 0x00 0x000000ff  A &= 0xff
 0016: 0x35 0xbb 0x00 0x00000080  if (A >= 128) goto 0204
 0017: 0x20 0x00 0x00 0x00000010  A = args[0]
 0018: 0x02 0x00 0x00 0x00000000  mem[0] = A
 0019: 0x20 0x00 0x00 0x00000018  A = args[1]
 0020: 0x61 0x00 0x00 0x00000000  X = mem[0]
 0021: 0xac 0x00 0x00 0x00000000  A ^= X
 0022: 0x02 0x00 0x00 0x00000001  mem[1] = A
 0023: 0x20 0x00 0x00 0x00000020  A = args[2]
 0024: 0x61 0x00 0x00 0x00000001  X = mem[1]
 0025: 0xac 0x00 0x00 0x00000000  A ^= X
 0026: 0x02 0x00 0x00 0x00000002  mem[2] = A
 0027: 0x20 0x00 0x00 0x00000028  A = args[3]
 0028: 0x61 0x00 0x00 0x00000002  X = mem[2]
 0029: 0xac 0x00 0x00 0x00000000  A ^= X
 0030: 0x02 0x00 0x00 0x00000003  mem[3] = A
 0031: 0x60 0x00 0x00 0x00000000  A = mem[0]
 0032: 0x61 0x00 0x00 0x00000001  X = mem[1]
 0033: 0x0c 0x00 0x00 0x00000000  A += X
 0034: 0x61 0x00 0x00 0x00000002  X = mem[2]
 0035: 0x0c 0x00 0x00 0x00000000  A += X
 0036: 0x61 0x00 0x00 0x00000003  X = mem[3]
 0037: 0x0c 0x00 0x00 0x00000000  A += X
 0038: 0x02 0x00 0x00 0x00000004  mem[4] = A
 0039: 0x60 0x00 0x00 0x00000000  A = mem[0]
 0040: 0x61 0x00 0x00 0x00000001  X = mem[1]
 0041: 0x1c 0x00 0x00 0x00000000  A -= X
 0042: 0x61 0x00 0x00 0x00000002  X = mem[2]
 0043: 0x0c 0x00 0x00 0x00000000  A += X
 0044: 0x61 0x00 0x00 0x00000003  X = mem[3]
 0045: 0x1c 0x00 0x00 0x00000000  A -= X
 0046: 0x02 0x00 0x00 0x00000005  mem[5] = A
 0047: 0x60 0x00 0x00 0x00000000  A = mem[0]
 0048: 0x61 0x00 0x00 0x00000001  X = mem[1]
 0049: 0x0c 0x00 0x00 0x00000000  A += X
 0050: 0x61 0x00 0x00 0x00000002  X = mem[2]
 0051: 0x1c 0x00 0x00 0x00000000  A -= X
 0052: 0x61 0x00 0x00 0x00000003  X = mem[3]
 0053: 0x1c 0x00 0x00 0x00000000  A -= X
 0054: 0x02 0x00 0x00 0x00000006  mem[6] = A
 0055: 0x60 0x00 0x00 0x00000000  A = mem[0]
 0056: 0x61 0x00 0x00 0x00000001  X = mem[1]
 0057: 0x1c 0x00 0x00 0x00000000  A -= X
 0058: 0x61 0x00 0x00 0x00000002  X = mem[2]
 0059: 0x1c 0x00 0x00 0x00000000  A -= X
 0060: 0x61 0x00 0x00 0x00000003  X = mem[3]
 0061: 0x0c 0x00 0x00 0x00000000  A += X
 0062: 0x02 0x00 0x00 0x00000007  mem[7] = A
 0063: 0x60 0x00 0x00 0x00000004  A = mem[4]
 0064: 0x61 0x00 0x00 0x00000005  X = mem[5]
 0065: 0x4c 0x00 0x00 0x00000000  A |= X
 0066: 0x02 0x00 0x00 0x00000008  mem[8] = A
 0067: 0x60 0x00 0x00 0x00000006  A = mem[6]
 0068: 0x61 0x00 0x00 0x00000007  X = mem[7]
 0069: 0x5c 0x00 0x00 0x00000000  A &= X
 0070: 0x61 0x00 0x00 0x00000008  X = mem[8]
 0071: 0xac 0x00 0x00 0x00000000  A ^= X
 0072: 0x02 0x00 0x00 0x00000008  mem[8] = A
 0073: 0x60 0x00 0x00 0x00000005  A = mem[5]
 0074: 0x61 0x00 0x00 0x00000006  X = mem[6]
 0075: 0x4c 0x00 0x00 0x00000000  A |= X
 0076: 0x02 0x00 0x00 0x00000009  mem[9] = A
 0077: 0x60 0x00 0x00 0x00000007  A = mem[7]
 0078: 0x61 0x00 0x00 0x00000004  X = mem[4]
 0079: 0x5c 0x00 0x00 0x00000000  A &= X
 0080: 0x61 0x00 0x00 0x00000009  X = mem[9]
 0081: 0xac 0x00 0x00 0x00000000  A ^= X
 0082: 0x02 0x00 0x00 0x00000009  mem[9] = A
 0083: 0x60 0x00 0x00 0x00000006  A = mem[6]
 0084: 0x61 0x00 0x00 0x00000007  X = mem[7]
 0085: 0x4c 0x00 0x00 0x00000000  A |= X
 0086: 0x02 0x00 0x00 0x0000000a  mem[10] = A
 0087: 0x60 0x00 0x00 0x00000004  A = mem[4]
 0088: 0x61 0x00 0x00 0x00000005  X = mem[5]
 0089: 0x5c 0x00 0x00 0x00000000  A &= X
 0090: 0x61 0x00 0x00 0x0000000a  X = mem[10]
 0091: 0xac 0x00 0x00 0x00000000  A ^= X
 0092: 0x02 0x00 0x00 0x0000000a  mem[10] = A
 0093: 0x60 0x00 0x00 0x00000007  A = mem[7]
 0094: 0x61 0x00 0x00 0x00000004  X = mem[4]
 0095: 0x4c 0x00 0x00 0x00000000  A |= X
 0096: 0x02 0x00 0x00 0x0000000b  mem[11] = A
 0097: 0x60 0x00 0x00 0x00000005  A = mem[5]
 0098: 0x61 0x00 0x00 0x00000006  X = mem[6]
 0099: 0x5c 0x00 0x00 0x00000000  A &= X
 0100: 0x61 0x00 0x00 0x0000000b  X = mem[11]
 0101: 0xac 0x00 0x00 0x00000000  A ^= X
 0102: 0x02 0x00 0x00 0x0000000b  mem[11] = A
 0103: 0x60 0x00 0x00 0x00000008  A = mem[8]
 0104: 0x15 0x25 0x00 0xf5ffc1f6  if (A == 4127179254) goto 0142
 0105: 0x15 0x14 0x00 0x7344aeee  if (A == 1933881070) goto 0126
 0106: 0x15 0x1f 0x00 0xfda6effe  if (A == 4255576062) goto 0138
 0107: 0x15 0x0a 0x00 0x638f7ca2  if (A == 1670347938) goto 0118
 0108: 0x15 0x0f 0x00 0xa2285400  if (A == 2720551936) goto 0124
 0109: 0x15 0x1a 0x00 0x8990fefe  if (A == 2307981054) goto 0136
 0110: 0x15 0x1d 0x00 0x9f576dd4  if (A == 2673307092) goto 0140
 0111: 0x15 0x0a 0x00 0xf6b9ebe2  if (A == 4139379682) goto 0122
 0112: 0x15 0x0f 0x00 0xf9e28bee  if (A == 4192373742) goto 0128
 0113: 0x15 0x14 0x00 0x1f9b8fb4  if (A == 530288564) goto 0134
 0114: 0x15 0x1d 0x00 0xefec86de  if (A == 4025255646) goto 0144
 0115: 0x15 0x0e 0x00 0xdf60093a  if (A == 3747612986) goto 0130
 0116: 0x15 0x03 0x00 0xb8af3fbe  if (A == 3098492862) goto 0120
 0117: 0x15 0x0e 0x00 0x7f01bbcc  if (A == 2130820044) goto 0132
 0118: 0x60 0x00 0x00 0x00000009  A = mem[9]
 0119: 0x15 0x32 0x54 0xf1cf5c2e  if (A == 4056898606) goto 0170 else goto 0204
 0120: 0x60 0x00 0x00 0x00000009  A = mem[9]
 0121: 0x15 0x20 0x52 0xb6af7dbe  if (A == 3064954302) goto 0154 else goto 0204
 0122: 0x60 0x00 0x00 0x00000009  A = mem[9]
 0123: 0x15 0x18 0x50 0xd6b9bde2  if (A == 3602496994) goto 0148 else goto 0204
 0124: 0x60 0x00 0x00 0x00000009  A = mem[9]
 0125: 0x15 0x22 0x4e 0x60fad508  if (A == 1627051272) goto 0160 else goto 0204
 0126: 0x60 0x00 0x00 0x00000009  A = mem[9]
 0127: 0x15 0x22 0x4c 0x77600ede  if (A == 2002783966) goto 0162 else goto 0204
 0128: 0x60 0x00 0x00 0x00000009  A = mem[9]
 0129: 0x15 0x1c 0x4a 0xf3b68ece  if (A == 4088827598) goto 0158 else goto 0204
 0130: 0x60 0x00 0x00 0x00000009  A = mem[9]
 0131: 0x15 0x24 0x48 0x4fe90926  if (A == 1340672294) goto 0168 else goto 0204
 0132: 0x60 0x00 0x00 0x00000009  A = mem[9]
 0133: 0x15 0x0c 0x46 0x7e1933ac  if (A == 2115580844) goto 0146 else goto 0204
 0134: 0x60 0x00 0x00 0x00000009  A = mem[9]
 0135: 0x15 0x24 0x44 0x1f9b8fb4  if (A == 530288564) goto 0172 else goto 0204
 0136: 0x60 0x00 0x00 0x00000009  A = mem[9]
 0137: 0x15 0x1c 0x42 0xcb94e7da  if (A == 3415533530) goto 0166 else goto 0204
 0138: 0x60 0x00 0x00 0x00000009  A = mem[9]
 0139: 0x15 0x0a 0x40 0xb9c2adfe  if (A == 3116543486) goto 0150 else goto 0204
 0140: 0x60 0x00 0x00 0x00000009  A = mem[9]
 0141: 0x15 0x0e 0x3e 0x0f01b94c  if (A == 251771212) goto 0156 else goto 0204
 0142: 0x60 0x00 0x00 0x00000009  A = mem[9]
 0143: 0x15 0x14 0x3c 0xf5efe5f6  if (A == 4126139894) goto 0164 else goto 0204
 0144: 0x60 0x00 0x00 0x00000009  A = mem[9]
 0145: 0x15 0x06 0x3a 0xa7ad8d4e  if (A == 2813168974) goto 0152 else goto 0204
 0146: 0x60 0x00 0x00 0x0000000a  A = mem[10]
 0147: 0x15 0x2e 0x38 0x7efd33a4  if (A == 2130523044) goto 0194 else goto 0204
 0148: 0x60 0x00 0x00 0x0000000a  A = mem[10]
 0149: 0x15 0x24 0x36 0xd6f33dda  if (A == 3606265306) goto 0186 else goto 0204
 0150: 0x60 0x00 0x00 0x0000000a  A = mem[10]
 0151: 0x15 0x26 0x34 0xbbdaa5e6  if (A == 3151668710) goto 0190 else goto 0204
 0152: 0x60 0x00 0x00 0x0000000a  A = mem[10]
 0153: 0x15 0x22 0x32 0x24a7ad2e  if (A == 614968622) goto 0188 else goto 0204
 0154: 0x60 0x00 0x00 0x0000000a  A = mem[10]
 0155: 0x15 0x2a 0x30 0xb7fdfcbe  if (A == 3086875838) goto 0198 else goto 0204
 0156: 0x60 0x00 0x00 0x0000000a  A = mem[10]
 0157: 0x15 0x10 0x2e 0x0f01b94c  if (A == 251771212) goto 0174 else goto 0204
 0158: 0x60 0x00 0x00 0x0000000a  A = mem[10]
 0159: 0x15 0x12 0x2c 0xb3bdaed6  if (A == 3015552726) goto 0178 else goto 0204
 0160: 0x60 0x00 0x00 0x0000000a  A = mem[10]
 0161: 0x15 0x22 0x2a 0x60ffd7bc  if (A == 1627379644) goto 0196 else goto 0204
 0162: 0x60 0x00 0x00 0x0000000a  A = mem[10]
 0163: 0x15 0x0c 0x28 0x5f785fd2  if (A == 1601724370) goto 0176 else goto 0204
 0164: 0x60 0x00 0x00 0x0000000a  A = mem[10]
 0165: 0x15 0x12 0x26 0x27aeff3e  if (A == 665780030) goto 0184 else goto 0204
 0166: 0x60 0x00 0x00 0x0000000a  A = mem[10]
 0167: 0x15 0x0e 0x24 0xc39dc1ca  if (A == 3281895882) goto 0182 else goto 0204
 0168: 0x60 0x00 0x00 0x0000000a  A = mem[10]
 0169: 0x15 0x1e 0x22 0x4d8f1f86  if (A == 1301225350) goto 0200 else goto 0204
 0170: 0x60 0x00 0x00 0x0000000a  A = mem[10]
 0171: 0x15 0x14 0x20 0x99ff4c6e  if (A == 2583645294) goto 0192 else goto 0204
 0172: 0x60 0x00 0x00 0x0000000a  A = mem[10]
 0173: 0x15 0x06 0x1e 0xe97d7d54  if (A == 3917315412) goto 0180 else goto 0204
 0174: 0x60 0x00 0x00 0x0000000b  A = mem[11]
 0175: 0x15 0x1b 0x1c 0x9f576dd4  if (A == 2673307092) goto 0203 else goto 0204
 0176: 0x60 0x00 0x00 0x0000000b  A = mem[11]
 0177: 0x15 0x19 0x1a 0x5b5cffe2  if (A == 1532821474) goto 0203 else goto 0204
 0178: 0x60 0x00 0x00 0x0000000b  A = mem[11]
 0179: 0x15 0x17 0x18 0xb9e9abf6  if (A == 3119098870) goto 0203 else goto 0204
 0180: 0x60 0x00 0x00 0x0000000b  A = mem[11]
 0181: 0x15 0x15 0x16 0xe97d7d54  if (A == 3917315412) goto 0203 else goto 0204
 0182: 0x60 0x00 0x00 0x0000000b  A = mem[11]
 0183: 0x15 0x13 0x14 0x8199d8ee  if (A == 2174343406) goto 0203 else goto 0204
 0184: 0x60 0x00 0x00 0x0000000b  A = mem[11]
 0185: 0x15 0x11 0x12 0x27bedb3e  if (A == 666819390) goto 0203 else goto 0204
 0186: 0x60 0x00 0x00 0x0000000b  A = mem[11]
 0187: 0x15 0x0f 0x10 0xf6f36bda  if (A == 4143147994) goto 0203 else goto 0204
 0188: 0x60 0x00 0x00 0x0000000b  A = mem[11]
 0189: 0x15 0x0d 0x0e 0x6ce6a6be  if (A == 1827055294) goto 0203 else goto 0204
 0190: 0x60 0x00 0x00 0x0000000b  A = mem[11]
 0191: 0x15 0x0b 0x0c 0xffbee7e6  if (A == 4290701286) goto 0203 else goto 0204
 0192: 0x60 0x00 0x00 0x0000000b  A = mem[11]
 0193: 0x15 0x09 0x0a 0x0bbf6ce2  if (A == 197094626) goto 0203 else goto 0204
 0194: 0x60 0x00 0x00 0x0000000b  A = mem[11]
 0195: 0x15 0x07 0x08 0x7fe5bbc4  if (A == 2145762244) goto 0203 else goto 0204
 0196: 0x60 0x00 0x00 0x0000000b  A = mem[11]
 0197: 0x15 0x05 0x06 0xa22d56b4  if (A == 2720880308) goto 0203 else goto 0204
 0198: 0x60 0x00 0x00 0x0000000b  A = mem[11]
 0199: 0x15 0x03 0x04 0xb9fdbebe  if (A == 3120414398) goto 0203 else goto 0204
 0200: 0x60 0x00 0x00 0x0000000b  A = mem[11]
 0201: 0x15 0x01 0x02 0xdd061f9a  if (A == 3708166042) goto 0203 else goto 0204
 0202: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0203: 0x06 0x00 0x00 0x00050000  return ERRNO(0)
 0204: 0x06 0x00 0x00 0x00050001  return ERRNO(1)

```

先頭2つの処理で777のシステムコールがそれ以降の処理で書かれているように見える。低級な命令が羅列しているが、x86等よりはかなり読みやすいのでこれをPythonで再現してz3で解く事を考える。

幸運にも、入力を加工して`mem`配列に入れるところはそのままPythonのコードとして使えたのでそのままコピペする。問題は続くif文の羅列で、`mem[8], mem[9], mem[10], mem[11]`に対する比較から構成されているが、この条件を手作業で取り出すのは面倒なので次のようなコードを用いた(`syscall777_if`はseccomp-toolsの結果から条件部分を取り出したもの)。

```python
with open("./syscall777_if.txt") as f:
    raw_lines = f.readlines()

lines = {}
start_lines = []

# parse
for l in raw_lines:
    if "A = mem[" in l:
        continue
    l = l.split()
    line_id = int(l[0][:-1])
    ope = " ".join(l[5:])
    ope = ope.replace("if", "")
    ope = ope.replace("else", "")
    ope = ope.replace("(A == ", "")
    ope = ope.replace(")", "")
    ope = ope.split(" goto ")
    ope = list(map(int, ope))
    lines[line_id] = ope

    if len(ope) == 2:
        start_lines.append((line_id, ope))

constraints = []
for line_id, (A, next_line) in start_lines:
    constraint = []
    constraint.append(A)
    A, next_line, _ = lines[next_line+1]
    constraint.append(A)
    A, next_line, _ = lines[next_line+1]
    constraint.append(A)
    A, next_line, _ = lines[next_line+1]
    constraint.append(A)
    constraints.append(constraint)

print(constraints)
```

というわけでここで取り出した値を用いてz3ソルバの条件に放り込み、解かせてフラグを得る。

## Code

```python
import z3
from z3 import LShR
from typing import Any


solver = z3.Solver()
bvs = [z3.BitVec(f"v_{i}", 32) for i in range(0xe)]

# constraints: ascii printable
for bv in bvs:
    solver.add(bv & 0xff < 128)
    solver.add(LShR(bv, 8) & 0xff < 128)
    solver.add(LShR(bv, 16) & 0xff < 128)
    solver.add(LShR(bv, 24) & 0xff < 128)

# constraints: flag format is known
solver.add(bvs[0] == int.from_bytes(b"zer0", "little"))
solver.add(bvs[1] == int.from_bytes(b"pts{", "little"))

# from other script
constraints = [[4127179254, 4126139894, 665780030, 666819390], [1933881070, 2002783966, 1601724370, 1532821474], [4255576062, 3116543486, 3151668710, 4290701286], [1670347938, 4056898606, 2583645294, 197094626], [2720551936, 1627051272, 1627379644, 2720880308], [2307981054, 3415533530, 3281895882, 2174343406], [2673307092, 251771212, 251771212, 2673307092], [4139379682, 3602496994, 3606265306, 4143147994], [4192373742, 4088827598, 3015552726, 3119098870], [530288564, 530288564, 3917315412, 3917315412], [4025255646, 2813168974, 614968622, 1827055294], [3747612986, 1340672294, 1301225350, 3708166042], [3098492862, 3064954302, 3086875838, 3120414398], [2130820044, 2115580844, 2130523044, 2145762244]]

for i in range(0xe):
    mem: list[Any] = [None for _ in range(0xe)]
    x0 = bvs[i]
    x1 = bvs[(i+1) % 0xe]
    x2 = bvs[(i+2) % 0xe]
    x3 = bvs[(i+3) % 0xe]

    args = [x0, x1, x2, x3]

    A = args[0]
    mem[0] = A
    A = args[1]
    X = mem[0]
    A ^= X
    mem[1] = A
    A = args[2]
    X = mem[1]
    A ^= X
    mem[2] = A
    A = args[3]
    X = mem[2]
    A ^= X
    mem[3] = A
    A = mem[0]
    X = mem[1]
    A += X
    X = mem[2]
    A += X
    X = mem[3]
    A += X
    mem[4] = A
    A = mem[0]
    X = mem[1]
    A -= X
    X = mem[2]
    A += X
    X = mem[3]
    A -= X
    mem[5] = A
    A = mem[0]
    X = mem[1]
    A += X
    X = mem[2]
    A -= X
    X = mem[3]
    A -= X
    mem[6] = A
    A = mem[0]
    X = mem[1]
    A -= X
    X = mem[2]
    A -= X
    X = mem[3]
    A += X
    mem[7] = A
    A = mem[4]
    X = mem[5]
    A |= X
    mem[8] = A
    A = mem[6]
    X = mem[7]
    A &= X
    X = mem[8]
    A ^= X
    mem[8] = A
    A = mem[5]
    X = mem[6]
    A |= X
    mem[9] = A
    A = mem[7]
    X = mem[4]
    A &= X
    X = mem[9]
    A ^= X
    mem[9] = A
    A = mem[6]
    X = mem[7]
    A |= X
    mem[10] = A
    A = mem[4]
    X = mem[5]
    A &= X
    X = mem[10]
    A ^= X
    mem[10] = A
    A = mem[7]
    X = mem[4]
    A |= X
    mem[11] = A
    A = mem[5]
    X = mem[6]
    A &= X
    X = mem[11]
    A ^= X
    mem[11] = A
    A = mem[8]

    solver_constraints = []
    for constraint in constraints:
        c1, c2, c3, c4 = constraint
        solver_constraints.append(z3.And(
            mem[8] == c1,
            mem[9] == c2,
            mem[10] == c3,
            mem[11] == c4
        ))

    solver.add(z3.Or(solver_constraints))

res = solver.check()
if res == z3.sat:
    flag = b""
    model = solver.model()
    for bv in bvs:
        x = model[bv].as_long()
        flag += x.to_bytes(4, "little")
    print(flag)
else:
    print("ha?")
```

## Flag

`zer0pts{B3rk3l3y_P4ck3t_F1lt3r:Y3t_4n0th3r_4ss3mbly}`

## References

- [Man page of PRCTL](https://linuxjm.osdn.jp/html/LDP_man-pages/man2/prctl.2.html)
- [david942j/seccomp-tools: Provide powerful tools for seccomp analysis](https://github.com/david942j/seccomp-tools)

[^1]: syscall命令ではなくラッパー関数
