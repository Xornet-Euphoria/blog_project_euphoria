+++
title = "LINE CTF 2023 Writeup"
date = 2023-03-26

[taxonomies]
tags = ["CTF", "Writeup", "Rev", "Web"]
+++


## Old Pal

次のようなPerlスクリプトが動いている。

<!-- more -->


```perl
#!/usr/bin/perl
use strict;
use warnings;

use CGI;
use URI::Escape;


$SIG{__WARN__} = \&warn;
sub warn {
    print("Hacker? :(");
    exit(1);
}


my $q = CGI->new;
print "Content-Type: text/html\n\n";


my $pw = uri_unescape(scalar $q->param("password"));
if ($pw eq '') {
    print "Hello :)";
    exit();
}
if (length($pw) >= 20) {
    print "Too long :(";
    die();
}
if ($pw =~ /[^0-9a-zA-Z_-]/) {
    print "Illegal character :(";
    die();
}
if ($pw !~ /[0-9]/ || $pw !~ /[a-zA-Z]/ || $pw !~ /[_-]/) {
    print "Weak password :(";
    die();
}
if ($pw =~ /[0-9_-][boxe]/i) {
    print "Do not punch me :(";
    die();
}
if ($pw =~ /AUTOLOAD|BEGIN|CHECK|DESTROY|END|INIT|UNITCHECK|abs|accept|alarm|atan2|bind|binmode|bless|break|caller|chdir|chmod|chomp|chop|chown|chr|chroot|close|closedir|connect|cos|crypt|dbmclose|dbmopen|defined|delete|die|dump|each|endgrent|endhostent|endnetent|endprotoent|endpwent|endservent|eof|eval|exec|exists|exit|fcntl|fileno|flock|fork|format|formline|getc|getgrent|getgrgid|getgrnam|gethostbyaddr|gethostbyname|gethostent|getlogin|getnetbyaddr|getnetbyname|getnetent|getpeername|getpgrp|getppid|getpriority|getprotobyname|getprotobynumber|getprotoent|getpwent|getpwnam|getpwuid|getservbyname|getservbyport|getservent|getsockname|getsockopt|glob|gmtime|goto|grep|hex|index|int|ioctl|join|keys|kill|last|lc|lcfirst|length|link|listen|local|localtime|log|lstat|map|mkdir|msgctl|msgget|msgrcv|msgsnd|my|next|not|oct|open|opendir|ord|our|pack|pipe|pop|pos|print|printf|prototype|push|quotemeta|rand|read|readdir|readline|readlink|readpipe|recv|redo|ref|rename|require|reset|return|reverse|rewinddir|rindex|rmdir|say|scalar|seek|seekdir|select|semctl|semget|semop|send|setgrent|sethostent|setnetent|setpgrp|setpriority|setprotoent|setpwent|setservent|setsockopt|shift|shmctl|shmget|shmread|shmwrite|shutdown|sin|sleep|socket|socketpair|sort|splice|split|sprintf|sqrt|srand|stat|state|study|substr|symlink|syscall|sysopen|sysread|sysseek|system|syswrite|tell|telldir|tie|tied|time|times|truncate|uc|ucfirst|umask|undef|unlink|unpack|unshift|untie|use|utime|values|vec|wait|waitpid|wantarray|warn|write/) {
    print "I know eval injection :(";
    die();
}
if ($pw =~ /[Mx. squ1ffy]/i) {
    print "You may have had one too many Old Pal :(";
    die();
}


if (eval("$pw == 20230325")) {
    print "Congrats! Flag is LINECTF{redacted}"
} else {
    print "wrong password :(";
    die();
};
```

最下部のif文にある通り`eval("$pw == 20230325")`がtrueになるような`$pw`を`password`というクエリパラメータとして渡せばフラグが手に入る。しかしソースコードを見てわかるように厳しいフィルターが掛けられており、次を満たさなくてはならない

- 20文字未満
- 英数字とハイフン、アンダースコア以外の文字の使用禁止
- 数字を1文字以上、アルファベットを1文字以上、ハイフンとアンダースコアのどちらか(あるいは両方)を1文字以上
- 数字の後に"boxe"が来てはならない(おそらく`0xdeadbeef`のような底を指定したリテラルを禁止するため)
- 多くの(全て?)予約語禁止
- `Mx. squ1ffy`に含まれる文字の禁止 (これだけ存在意義がよくわからなかった)

明らかに`20230325`は禁止だし、16進リテラル等も使えない。予約語もほとんど死んでいるようなので一見不可能に見えるが、上部にある`__WARN__`というものは特に予約語を並べたブラックリストには入っていない。したがってこれと同様にアンダースコアから始まって既に値が入ってそうなものが無いかを探すと`__LINE__`や`__FILE__`が見つかる。

ここで前者の`__LINE__`は実行時の行数が入っており「数値」である。ということは`<何らかの数字>-__LINE__`のようなものを`password`として送ると数値の減算として評価される。

というわけで、この`eval`が存在する行である51を20230325に足した20230376を用いて送るとフラグ手に……入らない。実はperlは実行時にコメントが除去されるとか何らかのマクロが暗黙の内に展開されるとか色々考えて引かれる数値の総当りしようと思ったが、CTFのDiscordには"warning"という圧が強いチャンネルが存在しており、そこで「Old Palは総当りしなくても解けるのでやめようね!」みたいな事が書いてあった。

仕方がないので配布された`docker-compose.yml`を使って`__LINE__`がどのように評価されるのかを調べてみたところ[^1]、どうやら「`eval`のある行」では無く、「`eval`の引数を1つのコードとみなした時の行」として評価されるようなので、`eval("__LINE__")`は1になる。

したがって、`20230326-__LINE__`をクエリパラメータに入れて送ればフラグが手に入る。

- flag: `LINECTF{3e05d493c941cfe0dd81b70dbf2d972b}`

## Fishing

exeが渡される。マルウェアで無い事を祈りながら動かしてみるとよくあるCrackMeのようである。

ひとまず動きを把握するためにデバッガ(x64dbg)でアタッチしてみるとアンチデバッグ機能が働いて終了する。main関数を特定する処理のために雑にブレークポイントを張って2分探索的に探索していたらついでにアンチデバッグ用の関数(デバッガがアタッチしているかどうかを調べる関数)を特定したのでパッチを当てても良かったのだが、入力を受け付けるのはデバッガがアタッチしているかどうかのチェック後だったので、そこまで処理を進めてからアタッチすることで回避した。

入力を受け付けている関数のデコンパイル結果は次のようになっている。

```c
undefined8 FUN_1400020fa(void)

{
  bool bVar1;
  undefined7 extraout_var;
  undefined8 in_R8;
  undefined8 in_R9;
  DWORD DStack_11c;
  undefined auStack_118 [264];
  HANDLE pvStack_10;
  
  FUN_140002547();
  FUN_140003bd0(&DAT_1400060b1,"Wanna catch a fish? Gimme the flag first",in_R8,in_R9);
  FUN_140003b70("%255s",auStack_118,0x100,in_R9);
  pvStack_10 = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,(LPTHREAD_START_ROUTINE)&LAB_140001e2f,
                            auStack_118,4,&DStack_11c);
  if (pvStack_10 == (HANDLE)0x0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  bVar1 = FUN_140002010(pvStack_10);
  if ((int)CONCAT71(extraout_var,bVar1) != 0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  ResumeThread(pvStack_10);
  WaitForSingleObject(pvStack_10,0xffffffff);
  CloseHandle(pvStack_10);
  return 0;
}
```

なお、先に断っておくとこのバイナリには難読化が施されており、このデコンパイル結果に相当するディスアセンブル結果を抜粋すると次のようになっている。

```txt
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined8 __fastcall FUN_1400020fa(void)
                               assume GS_OFFSET = 0xff00000000
             undefined8        RAX:8          <RETURN>
             undefined1        Stack[-0xd8]:1 local_d8                                XREF[1]:     140002102(*)  
                             FUN_1400020fa                                   XREF[3]:     FUN_140001154:14000143f(c), 
                                                                                          14000810c(*), 140008114(*)  
       1400020fa 55              PUSH       RBP
       1400020fb 48 81 ec        SUB        RSP,0x150
       140002102 48 8d ac        LEA        RBP=>local_d8,[RSP + 0x80]
       14000210a e8 38 04        CALL       FUN_140002547                                    undefined FUN_140002547(void)
                             LAB_14000210f+1                                 XREF[0,1]:   14000210f(j)  
       14000210f eb ff           JMP        LAB_14000210f+1
       140002111 c2 eb ff        RET        0xffeb
       140002114 ca 48 8d        RETF       0x8d48
       140002117 05 6c 3f        ADD        EAX,0x3f6c
       14000211c 48 89 c2        MOV        RDX,RAX
       14000211f 48 8d 05        LEA        RAX,[DAT_1400060b1]                              = 25h    %
       140002126 48 89 c1        MOV        RCX=>DAT_1400060b1,RAX                           = 25h    %
       140002129 e8 a2 1a        CALL       FUN_140003bd0                                    undefined4 FUN_140003bd0(undefin
                             LAB_14000212e+1                                 XREF[0,1]:   14000212e(j)  
       14000212e eb ff           JMP        LAB_14000212e+1
       140002130 c7              ??         C7h
                             LAB_140002131+1                                 XREF[0,1]:   140002131(j)  
       140002131 eb ff           JMP        LAB_140002131+1
       140002133 cf              IRETD
       140002134 48 8d 45 c0     LEA        RAX,[RBP + -0x40]
       140002138 41 b8 00        MOV        R8D,0x100
       14000213e 48 89 c2        MOV        RDX,RAX
       140002141 48 8d 05        LEA        RAX,[s_%255s_1400060b6]                          = "%255s"

```

厄介なことに`JMP LAB_14000...+1`という命令によって`eb ff`の次の命令はこの命令に含まれる`ff`から始まる。ディスアセンブルはそこを修正してくれるような気の利いた事をやってくれないが、どうもデコンパイル結果はまともなようなのでひとまず頭の片隅に入れておく程度で読む。

デコンパイル結果に戻ってWindowsの事を何も知らないが、適当に関数呼び出しや関数ポインタっぽいところをクリックして中を覗いてみると、どういうわけか`pvStack_10 = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,(LPTHREAD_START_ROUTINE)&LAB_140001e2f,auStack_118,4,&DStack_11c);`内の`LAB_140001e2f`が呼び出されているようである。このラベルから始まる部分のデコンパイル結果は次の通り

```c
undefined8 UndefinedFunction_140001e2f(byte *param_1)

{
  int iVar1;
  size_t sVar2;
  undefined8 uStack_68;
  undefined8 uStack_60;
  undefined4 uStack_58;
  undefined8 uStack_48;
  undefined8 uStack_40;
  undefined8 uStack_38;
  undefined uStack_30;
  undefined7 uStack_2f;
  undefined uStack_28;
  undefined8 uStack_27;
  byte *pbStack_18;
  int iStack_c;
  
  uStack_48 = 0xb534f0bd5a9fbed0;
  uStack_40 = 0xd7aeba99e2fb6fd0;
  uStack_38 = 0x3b04522c22dd536;
  uStack_30 = 0x9d;
  uStack_2f = 0x2acc28c7536663;
  uStack_28 = 0x2b;
  uStack_27 = 0x3a4660e39b09bb14;
  uStack_68 = 0x4e505fa94f652223;
  uStack_60 = 0x5d3126355d2c2d5d;
  uStack_58 = 0x494d4d26;
  sVar2 = strlen((char *)param_1);
  iStack_c = (int)sVar2;
  pbStack_18 = (byte *)malloc((longlong)(iStack_c + 1));
  if (pbStack_18 == (byte *)0x0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  memset(pbStack_18,0,(longlong)(iStack_c + 1));
  FUN_140001cdf((longlong)param_1,iStack_c);
  FUN_140001d33((longlong)param_1,iStack_c);
  FUN_140001d87((longlong)&uStack_68,0x14);
  FUN_140001ddb((longlong)&uStack_68,0x14);
  FUN_140002310(param_1,iStack_c,(byte *)&uStack_68,0x14,pbStack_18);
  if (iStack_c == 0x29) {
    iVar1 = memcmp(&uStack_48,pbStack_18,0x29);
    if (iVar1 == 0) {
      puts("Correct! You get a fish!");
      goto LAB_140001ff0;
    }
  }
  puts("Too bad! Not even a nibble...");
LAB_140001ff0:
  free(pbStack_18);
  return 0;
}
```

デバッガで値を覗いたりした結果から、`param_1`は入力を指すポインタである事がわかっている。その後`FUN_140001cdf`と`FUN_140001d33`によって入力が加工され、`FUN_140001d87`と`FUN_140001ddb`で`uStack_68`というスタック上におかれた配列が加工される。

これら4つの関数はfor文で1文字ずつ加工するという非常に簡単な処理なのだが、どうも手元で再現した結果と合わず、デバッガで追ってみると途中で謎の場所に飛んだりしたため、静的解析は諦めて動的解析で各バイトがどう変換されるかを見る。

前者の入力を処理する2つの関数は1文字ずつの変換かつ、同一バイトなら場所(インデックス)に依存しないようなので`LINECTF{0123456789abcdef0123456789abcdef}`[^2]を入力として与えてどのようなバイトに変換されるかをデバッガで特定して変換テーブルを構成した。

後者に関しては`uStack_68`は実行ごとに変わるわけではなく、関数の処理も入力に依存しないようなので`"m4g1KaRp_ON_7H3_Hook"`という固定の値になる[^3]。

残る`FUN_140002310`は次のようになっている(内部の`create_SBOX_140002230`という関数は、ある配列がSBOXだと思って名付けたが、特にそんな事は無かった)

```c
void FUN_140002310(byte *inp,int inp_len,byte *key_l14,int const_14,byte *empty)

{
  byte box [258];
  byte local_16;
  byte local_15;
  int i;
  uint local_10;
  uint j;
  
  memset(box,0,0x100);
  create_SBOX_140002230(box,key_l14,const_14);
  j = 0;
  local_10 = 0;
  for (i = 0; i < inp_len; i = i + 1) {
    j = j + 1 & 0xff;
    local_10 = local_10 + box[j] & 0xff;
    local_15 = box[j];
    box[j] = box[local_10];
    box[local_10] = local_15;
    local_16 = box[(int)(uint)(byte)(box[local_10] + box[j])];
    empty[i] = inp[i] ^ box[(int)(uint)(byte)(box[local_10] + box[j])] ^ (char)local_10 - 0x18U;
  }
  return;
}
```

`key_l14`は先程の`m4g1KaRp_ON_7H3_Hook`で、`empty`は呼び出し元(`140001e2f`)でmemsetで定義された空の配列である。`create_SBOX_140002230`も`key_l14`が固定の値なので毎度同じ値を`box`に代入する。この`box`を用いて入力と適当に演算した結果が`empty`に代入され、最終的に`140001e2f`の`memcmp`がある場所で比較されている。`memcmp`の比較先を`target`とおくと、`target[i] = inp[i] ^ local_16 ^ local_10 - 0x18`となるので、各`i`に対して`inp[i] = target[i] ^ local_16 ^ local_10 - 0x18`を計算してやれば先に加工された`inp`が得られる。そしてこれを先程構成した変換テーブルを用いて戻してあげるとフラグが手に入る。次のようなコードを用いた

```python
key = b"m4g1KaRp_ON_7H3_Hook"
sbox = [i for i in range(0x100)]

local_10 = 0
for j in range(0x100):
    local_10 = key[j % 0x14] + sbox[j] + local_10
    local_10 &= 0xff
    sbox[j], sbox[local_10] = sbox[local_10], sbox[j]

line = ""
for i, c in enumerate(sbox):
    line += f"{c:02x} "
    if i % 16 == 15:
        line += "\n"


desired_inp = []
target = list(map(lambda x: int(x, 16), "D0 BE 9F 5A BD F0 34 B5 D0 6F FB E2 99 BA AE D7 36 D5 2D C2 22 45 B0 03 9D 63 66 53 C7 28 CC 2A 2B 14 BB 09 9B E3 60 46 3A".split()))

j = 0
local_10 = 0
for i in range(0x29):
    j += 1
    local_10 += sbox[j]
    local_10 &= 0xff
    sbox[j], sbox[local_10] = sbox[local_10], sbox[j]
    local_16 = sbox[(sbox[local_10] + sbox[j]) & 0xff]
    xored = local_16 ^ ((local_10 - 0x18) & 0xff)
    desired_inp.append(target[i] ^ xored)

inp = "LINECTF{0123456789abcdef0123456789abcdef}"
converted_inp = list(map(lambda x: int(x, 16),"49 21 59 01 F1 89 19 B0 66 5E 76 6E 86 7E 96 8E A6 9E E0 F8 F0 08 00 18 66 5E 76 6E 86 7E 96 8E A6 9E E0 F8 F0 08 00 18 C0".split()))

d = {}
for x,y in zip(inp, converted_inp):
    d[y] = x

flag = ""
for x in desired_inp:
    flag += d[x]

print(flag)
```

- flag: `LINECTF{e255cda25f1a8a634b31458d2ec405b6}`

## Jumpit

`assets`や`lib`、`AndroidManifest.xml`等が与えられることから、おそらくunzipしたapkの中身だと思われる。

`classes.dex`も与えられているが、[APK decompiler - decompile Android .apk ✓ ONLINE ✓](http://www.javadecompilers.com/apk)に食わせても特に芳しい結果は得られないので`lib`に当たりをつける。

`arm64-v8a`と`armeabi-v7a`の2つのディレクトリが存在するが、多分どっちを解析しても特に差異は無いと思うので前者を覗くと`libil2cpp.so`と`libmain.so`と`libunity.so`が見つかった。

`libmain.so`はそれっぽい名前をしている割にはデコンパイルも即座に終わり、セットアップ系の処理しかしないようである。そこで`libil2cpp.so`に注目して色々調べてみると、どうやらC#の中間言語をC++に変換するlibil2cppと呼ばれるツール(?)が存在しており、それによって作られたコードをコンパイルしたネイティブライブラリがこれらしい。

Ghidraにぶち込んでも一生0%から進まない解析のプログレスバーを眺めるだけだったので、解析ツールが出回っていると信じて調べてみると[Perfare/Il2CppDumper: Unity il2cpp reverse engineer](https://github.com/Perfare/Il2CppDumper)が見つかる。

これに先程の`libil2cpp.so`と`assets/bin/Data/Managed/Metadata/global-metadata.dat`を指定して実行するとヘッダファイルや、関数やクラスの型定義だけ書かれたC#コード、元のC#から作られたと思われるdll、定義済みの文字列をまとめたJSON等が手に入る。

とりあえずdllをdnSpyに入れてみると、関数やクラスメソッド等の実装は見れないものの、rva(ライブラリの配置アドレスから見た相対的なアドレス)や関数定義が見れるので眺めていたら`GameManager`というクラスに`GetFlag`という如何にもなメソッドを見つけた。該当箇所をGhidraで見ると次のようになっている。

```c
void GameManager$$GetFlag(long param_1,undefined8 param_2,int param_3)

{
  ulong uVar1;
  undefined8 uVar2;
  long *plVar3;
  
  if ((DAT_00c141f3 & 1) == 0) {
    thunk_FUN_0037eb0c(&StringLiteral_3273);
    thunk_FUN_0037eb0c(&StringLiteral_2608);
    DAT_00c141f3 = 1;
  }
  if ((param_3 == 0x1077) &&
     (uVar1 = System.String$$op_Equality(param_2,StringLiteral_3273,0), (uVar1 & 1) != 0)) {
    uVar2 = GameManager$$DecryptECB(uVar1,*(undefined8 *)(param_1 + 0x50),StringLiteral_2608);
    plVar3 = *(long **)(param_1 + 0x30);
    if (plVar3 != (long *)0x0) {
                    /* WARNING: Could not recover jumptable at 0x008b7e34. Too many branches */
                    /* WARNING: Treating indirect jump as call */
      (**(code **)(*plVar3 + 0x558))(plVar3,uVar2,*(undefined8 *)(*plVar3 + 0x560));
      return;
    }
                    /* WARNING: Subroutine does not return */
    FUN_003d9d08();
  }
  return;
}
```

あくまでGuessに過ぎないが`GameManager$$DecryptECB`の実行結果がフラグなんじゃないかと当たりを付けてどのような値が渡されているかを調べる。`GameManager$$DecryptECB`の関数定義は`public string DecryptECB(string keyString, string text) { }`のようになっており、デコンパイル結果を眺めると第3引数を` System.Convert$$FromBase64String`に渡してから色々としているようである(長いので関数のデコンパイル結果は略)。

変数名とデコンパイル結果からGuessすると、おそらく第2引数が鍵(を何らかの形でエンコードしたものか生データ)で、第3引数が暗号文だと思われる。第3引数は`StringLiteral_2608`という形でバイナリ上では何らかのポインタが入っているようにしか見えないが、il2CppDumperはこの文字列が何なのかを教えてくれるJSONも吐いてくれるのでこれと照合すると文字列の実体が手に入る。これは直前に述べたようにbase64でエンコードされているので、後で復号する時のためにC#のbase64用の関数である[Convert.FromBase64String(String)](https://learn.microsoft.com/ja-jp/dotnet/api/system.convert.frombase64string?view=net-7.0)でデコードしておいた[^4]。

第2引数は、`param_1 + 0x50`という形なので多分`param_1`が何らかのクラスであり、`DecryptECB`が関数の定義の上では2引数しか無い事を考慮してPythonでいう`self`相当だと仮定すると、`GameManager`のここに対応するフィールドに鍵が入っていると考えられる。ここで、`GameManager`の定義を見てみると次のようになっている。

```csharp
public class GameManager : MonoBehaviour // TypeDefIndex: 2677
{
	// Fields
	private int scoreTarget; // 0x18
	private int score; // 0x1C
	public GameObject obstacle; // 0x20
	public Transform spawnPoint; // 0x28
	public TextMeshProUGUI scoreText; // 0x30
	public GameObject playButton; // 0x38
	public GameObject player; // 0x40
	public string rootDetectedMsg; // 0x48
	private string finalKey; // 0x50

	// Methods

	// RVA: 0x7B7908 Offset: 0x7B7908 VA: 0x7B7908
	private void Start() { }

	// RVA: 0x7B7A20 Offset: 0x7B7A20 VA: 0x7B7A20
	private void Update() { }

	[IteratorStateMachineAttribute] // RVA: 0x2520F0 Offset: 0x2520F0 VA: 0x2520F0
	// RVA: 0x7B7A24 Offset: 0x7B7A24 VA: 0x7B7A24
	private IEnumerator SpawnObstacles() { }

	// RVA: 0x7B7AC8 Offset: 0x7B7AC8 VA: 0x7B7AC8
	private void ScoreUp() { }

	// RVA: 0x7B7D88 Offset: 0x7B7D88 VA: 0x7B7D88
	public void GetFlag(string text, int score) { }

	// RVA: 0x7B81A0 Offset: 0x7B81A0 VA: 0x7B81A0
	public void GameStart() { }

	// RVA: 0x7B82B0 Offset: 0x7B82B0 VA: 0x7B82B0
	public string EncryptECB(string keyString, string text) { }

	// RVA: 0x7B7E4C Offset: 0x7B7E4C VA: 0x7B7E4C
	public string DecryptECB(string keyString, string text) { }

	// RVA: 0x7B79A4 Offset: 0x7B79A4 VA: 0x7B79A4
	private bool IsDeviceRooted() { }

	// RVA: 0x7B85F8 Offset: 0x7B85F8 VA: 0x7B85F8
	public void .ctor() { }
}
```

オフセット0x50に対応するメンバが`finalKey`であり、名前からしてAESの鍵だと考えられる。というわけでGhidraの方でここに値をセットしている処理を探す。

`Start`や`GameStart`辺りが名前だけは怪しいメソッドだが、デコンパイル結果が正直なら`finalKey`に対して何らかの処理をしているようには思えない。結局生えているメソッドを片っ端から見ていった結果、`ScoreUp`メソッドに該当する処理があった。抜粋すると次のようになっている。

```c
  if (iVar2 < 500000) {
    if (iVar2 < 3000) {
      if (iVar2 == 10) {
        uVar1 = *(undefined8 *)(param_1 + 0x50);
        puVar3 = &StringLiteral_679;
        goto LAB_008b7ce8;
      }
      if (iVar2 == 200) {
        uVar1 = *(undefined8 *)(param_1 + 0x50);
        puVar3 = &StringLiteral_107;
        goto LAB_008b7ce8;
      }
    }
    else {
      if (iVar2 == 3000) {
        uVar1 = *(undefined8 *)(param_1 + 0x50);
        puVar3 = &StringLiteral_297;
        goto LAB_008b7ce8;
      }
      if (iVar2 == 40000) {
        uVar1 = *(undefined8 *)(param_1 + 0x50);
        puVar3 = &StringLiteral_2389;
        goto LAB_008b7ce8;
      }
    }
  }
```

`StringLiteral_...`を点数が低い順に結合していくようなのでこの処理を追ってみると`"Cia!fo2MPXZQvaVA39iuiokE6cvZUkqx"`が得られる。

これで、AESの暗号文と鍵が得られたので関数名の通りECBモードで復号する。用いたコードは次の通り

```python
from Crypto.Cipher import AES

ct = "71-61-93-99-E0-E5-16-C6-04-14-8F-44-E6-61-FF-78-29-D0-D5-23-65-58-99-57-8F-E9-25-3C-B6-D6-4B-F7-3F-D6-F2-3B-50-FA-CE-E1-DA-78-D6-ED-AD-4C-63-36"
ct = list(map(lambda x: int(x,16), ct.split("-")))

print(ct)
print(len(ct))

key = "Cia!fo2MPXZQvaVA39iuiokE6cvZUkqx"
print(len(key))

cipher = AES.new(key.encode(), AES.MODE_ECB)
pt = cipher.decrypt(bytes(ct))

print(pt)
```

- flag: `LINECTF{1c4f5397798d9150ce1b8e10e9d99657}`

---

[^1]: ちなみに、Dockerコンテナは特に問題なく生えたものの、`localhost:<port>`にアクセスしても迫真"It Works!"先輩しか表示されず、`localhost:<port>/cgi-bin/main.pl`にアクセスしないと駄目なことに気付かなくて1時間ぐらい溶かした

[^2]: フラグフォーマットは`LINECTF{[0-9a-f]{32}}`だったのでこの程度の探索で済んでいる

[^3]: `m4g1KaRp`部分が何かわからないのでググったら「コイキング」の英名らしい

[^4]: C#の環境が無いのでpaiza.ioを使った。これ以外にもPHPとPerlとJavaがCTFで出た時によくお世話になっている
