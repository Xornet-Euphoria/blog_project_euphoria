+++
title = "DownUnderCTF 2022 - click the flag"
date = 2023-03-09

[taxonomies]
tags = ["CTF", "Writeup", "rev", "apk"]
+++


- 問題ファイル: [Challenges_2022_Public/rev/click-the-flag/publish at main · DownUnderCTF/Challenges_2022_Public](https://github.com/DownUnderCTF/Challenges_2022_Public/tree/main/rev/click-the-flag/publish)

## TL;DR

- ネイティブライブラリ(ELF)を使っているapkが与えられて、正しい旗を一生タップし続けるだけのゲームに勝ち続ける事ができればフラグが出力される
- そんなものに耐えられるはずも無いのでApkをアンパックし、ゲーム本体のjavaコードとネイティブライブラリを読む
- 実際のゲームの動作と対応する場所を、javaとELFの双方を良い感じに読みながらフラグの出力処理を特定し、再現してフラグを得る

## Writeup

apkが与えられる。悪意のあるコードが入っていない事を祈りながら[^1]、手元の端末にインストールして実行してみるとひたすらフラグをタップするゲームが始まる。どうやら全部で85ラウンドあるようで、ラウンドクリアごとにフラグが1文字ずつ開示される仕組みらしい。

問題は1回でもミスタップ(タップし損なったり、ハズレの赤い旗をタップする)してしまうと失敗な上に、1ラウンドはだいたい15秒な上にインターバルはラウンドごとに5秒ずつ増える。当然、こんな状況下で85ラウンドもやってられないのでちゃんとapkを解析することにする。

apkの問題はほとんど解いた事が無いので色々なapkに関連するWriteup[^2]を読んでいたら、[Apktool](https://ibotpeaches.github.io/Apktool/)というものがそこかしこで使われていたのでこれを使ってみる。どうやら、apkを食わせるとネイティブライブラリやアセット、smaliと呼ばれる中間言語(?)等を吐き出してくれる機能があるらしい。

せっかく吐き出してもらったsmaliコードだが、これを読んでも何もわかるはずがない。そういえばjarのデコンパイルはよく聞くし、apkからjarに変換してデコンパイル出来ないかと考えていたら、いつもお世話になっている[Java decompiler online](http://www.javadecompilers.com/)が[APK decompiler - decompile Android .apk ✓ ONLINE ✓](http://www.javadecompilers.com/apk)というサイトも運営していた。

これを使ってみると大量のjavaにコードが得られるが、重要なのは`source/com/example/chall/MainActivity.java`で雑に読んでいくと、前述のゲームっぽい処理が行われていることがわかる。部分的に抜粋すると次の通り。

```java
public final void run() {
    String str;
    TextView textView;
    MainActivity mainActivity = this.f2105a;
    if (mainActivity.f2101a % 15 == 0) {
        Object[] ur = mainActivity.mo2409ur();
        C1204a aVar = this.f2105a.f2104a;
        if (aVar != null) {
            StringBuilder f = C0017a.m29f("Round ");
            f.append(ur[0]);
            f.append("/85");
            ((TextView) aVar.f4392e).setText(f.toString());
            if (((Integer) ur[0]).intValue() > 1) {
                C1204a aVar2 = this.f2105a.f2104a;
                if (aVar2 != null) {
                    TextView textView2 = (TextView) aVar2.f4391d;
                    StringBuilder sb = new StringBuilder();
                    C1204a aVar3 = this.f2105a.f2104a;
                    if (aVar3 != null) {
                        sb.append(((TextView) aVar3.f4391d).getText());
                        sb.append((char) ((Integer) ur[1]).intValue());
                        textView2.setText(sb.toString());
                    } else {
                        C1062d.m3340B("binding");
                        throw null;
                    }
                } else {
                    C1062d.m3340B("binding");
                    throw null;
                }
            }
            Handler handler = this.f2105a.f2102a;
            if (handler != null) {
                handler.removeCallbacksAndMessages((Object) null);
                if (((Integer) ur[0]).intValue() <= 10) {
                    int intValue = ((Integer) ur[0]).intValue() * 5000;
                    C1204a aVar4 = this.f2105a.f2104a;
                    if (aVar4 != null) {
                        StringBuilder f2 = C0017a.m29f("Starting round ");
                        f2.append(ur[0]);
                        f2.append(" in ");
                        f2.append(intValue / 1000);
                        f2.append(" seconds...");
                        ((TextView) aVar4.f4390c).setText(f2.toString());
                        MainActivity mainActivity2 = this.f2105a;
                        Handler handler2 = mainActivity2.f2102a;
                        if (handler2 != null) {
                            handler2.postDelayed(new C0519a(mainActivity2), (long) intValue);
                        } else {
                            C1062d.m3340B("mainHandler");
                            throw null;
                        }
                    } else {
                        C1062d.m3340B("binding");
                        throw null;
                    }
                } else {
                    if (((Integer) ur[0]).intValue() <= 85) {
                        C1204a aVar5 = this.f2105a.f2104a;
                        if (aVar5 != null) {
                            textView = (TextView) aVar5.f4390c;
                            str = "You've reached the end of the trial! Please upgrade for $1337 to access the full version.";
                        } else {
                            C1062d.m3340B("binding");
                            throw null;
                        }
                    } else {
                        C1204a aVar6 = this.f2105a.f2104a;
                        if (aVar6 != null) {
                            textView = (TextView) aVar6.f4390c;
                            str = "Congrats, you win!";
                        } else {
                            C1062d.m3340B("binding");
                            throw null;
                        }
                    }
                    textView.setText(str);
                }
                this.f2105a.f2101a++;
                return;
            }
            C1062d.m3340B("mainHandler");
            throw null;
        }
        C1062d.m3340B("binding");
        throw null;
    }
```

表示テキストにも関与しており、ところどころ登場する`ur`という変数が気になったので定義を見ると`Object[] ur = mainActivity.mo2409ur();`のようになっている。この関数は`public final native Object[] mo2409ur();`のように定義されており、ネイティライブラリから読み込んでいるらしい。そういえばApktoolでアンパックした中に`lib`というフォルダがあったので覗いてみたら`lib/x86_64/libchall.so`というバイナリが見つかった。こいつをGhidraとIDAに食わせてみると`Java_com_example_chall_MainActivity_ur`という関数が見つかる。IDAでのデコンパイル結果は次の通り

```c
__int64 __fastcall Java_com_example_chall_MainActivity_ur(__int64 a1)
{
  char v1; // al
  int v3; // r14d
  __int64 v4; // rax
  __int64 v5; // r13
  int v6; // r15d
  __int64 v7; // r12
  int v8; // eax
  int v9; // r8d
  int v10; // r9d
  __int64 v11; // rax
  __int64 v12; // rax
  int v13; // ebp
  int v14; // eax
  int v15; // r8d
  int v16; // r9d
  __int64 v17; // rax
  char v19; // [rsp-8h] [rbp-38h]
  char v20; // [rsp-8h] [rbp-38h]

  v19 = v1;
  v3 = *(char *)(*((_QWORD *)&game_state + 1) + word_2C450[game_state - 1]);
  ++game_state;
  ++*((_WORD *)&game_state + 1);
  v4 = (*(__int64 (__fastcall **)(__int64, const char *))(*(_QWORD *)a1 + 48LL))(a1, "java/lang/Object");
  v5 = (*(__int64 (__fastcall **)(__int64, __int64, __int64, _QWORD))(*(_QWORD *)a1 + 1376LL))(a1, 2LL, v4, 0LL);
  v6 = game_state;
  v7 = (*(__int64 (__fastcall **)(__int64, const char *))(*(_QWORD *)a1 + 48LL))(a1, "java/lang/Integer");
  v8 = (*(__int64 (__fastcall **)(__int64, __int64, const char *, const char *))(*(_QWORD *)a1 + 264LL))(
         a1,
         v7,
         "<init>",
         "(I)V");
  v11 = _JNIEnv::NewObject(a1, v7, v8, v6, v9, v10, v19);
  (*(void (__fastcall **)(__int64, __int64, _QWORD, __int64))(*(_QWORD *)a1 + 1392LL))(a1, v5, 0LL, v11);
  v12 = (*(__int64 (__fastcall **)(__int64, const char *))(*(_QWORD *)a1 + 48LL))(a1, "java/lang/Integer");
  v13 = v12;
  v14 = (*(__int64 (__fastcall **)(__int64, __int64, const char *, const char *))(*(_QWORD *)a1 + 264LL))(
          a1,
          v12,
          "<init>",
          "(I)V");
  v17 = _JNIEnv::NewObject(a1, v13, v14, v3 ^ 0x42u, v15, v16, v20);
  (*(void (__fastcall **)(__int64, __int64, __int64, __int64))(*(_QWORD *)a1 + 1392LL))(a1, v5, 1LL, v17);
  return v5;
}
```

`game_state`変数は名前の通りゲームの状態を管理する変数で、Ghidraのデコンパイル結果やこのライブラリを呼び出しているjavaコードと比べてみると、先頭がラウンド数で後半はなんらかのポインタが入っているようである。非常に雑かつGuessyな読み方をしているが、`v3`に入った値が`v17`を生成する過程で0x42と排他的論理和をとり、その後になんらかのメソッドを呼んでreturnし、返された先ではフラグの文字列に関連する値が生えていることから、`v3 ^ 0x42`がフラグの値ではないかと当たりを付ける。

となると、気になるのは`&game_state + 1`で、Ghidraで調べると0x38c00に`game_state`を指すポインタが入っており、この関数(以下、`ur`関数と呼ぶ)以外でも参照されているため、それらを読んでいく。

特に重要そうだったのは、`Java_com_example_chall_MainActivity_init`と呼ばれる関数(以下、`init`)で(今度はGhidraのデコンパイル結果の方がわかりやすかったので)Ghidraのデコンパイル結果は次のようになっている。

```c
void Java_com_example_chall_MainActivity_init(long *param_1,undefined8 param_2,undefined8 param_3)

{
  void *__src;
  long in_FS_OFFSET;
  undefined local_29;
  long local_28;
  
  local_28 = *(long *)(in_FS_OFFSET + 0x28);
  DAT_00039040 = 0;
  _DAT_00039042 = 0;
  __src = (void *)(**(code **)(*param_1 + 0x5c0))(param_1,param_3,&local_29);
  (**(code **)(*param_1 + 0x600))(param_1,param_3,__src,2);
  _DAT_00039048 = calloc(0x8000,1);
  memcpy(_DAT_00039048,__src,0x8000);
  if (*(long *)(in_FS_OFFSET + 0x28) == local_28) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

フィーリングで読むと、何らかの値を0x39048にコピーしているようで、ここは上記のIDAのデコンパイル結果の`&game_state + 1`に対応している(おそらく)。問題は`__src`変数が何者なのか全く見当がつかない。`init`を呼び出しているjavaのコードを探してみると、次のような処理が見つかる

```java
if (aVar != null) {
    ((TextView) aVar.f4393f).setText(stringFromJNI());
    InputStream open = getAssets().open("flag_img.png");
    C1062d.m3345h(open, "assetManager.open(\"flag_img.png\")");
    byte[] bArr = new byte[32768];
    open.read(bArr, 0, 32768);
    init(bArr);
    View findViewById = findViewById(R.id.restartButton);
    C1062d.m3345h(findViewById, "findViewById<Button>(R.id.restartButton)");
    Button button2 = (Button) findViewById;
    this.f2103a = button2;
    button2.setOnClickListener(new C1190a(this, bArr));
    this.f2102a = new Handler(Looper.getMainLooper());
    mo2407s();
    return;
}
```

`init`にはどうやら`bArr`が渡されているようである。直前の処理を読んでみると、アセットの`flag_img.png`のバイト列が入っているように見える。とすると、`__src = (void *)(**(code **)(*param_1 + 0x5c0))(param_1,param_3,&local_29);`は多分`byte[]`の何らかのメソッドを呼び出して`flag_img.png`のバイト列を得ていると考えられる。

このGuessによって、各ラウンドの終わりではゲーム以外でも次の事を行っていると考えられる。

1. `i = word_2C450[round]`を得る
2. `&game_state + 1`のアドレスを配列(の先頭)とみなして`i`番目の要素を取得し、`v3`とする。これは`flag_img.png`の`i`バイト目を得ていることになる
3. `v3 ^ 0x42`を計算して(`game_state`に関連させる等の)何らかの形でjavaコード側にい渡す
4. フラグとして出力する

というわけで以上の事を行うコードを書いて再現すれば良い。

## Code

```python
# from IDA
idxes = [0x6ED1, 0x6F59, 0x58DC, 0x53E, 0x2CCB, 0x7F5, 0x5E2F, 0x52FF,
0x4B36, 0x18E1, 0x21D1, 0x4725, 0x500, 0x1DE0, 0x7C36, 0x7D6A,
0x6049, 0x2D30, 0x57F6, 0x57C8, 0x54D1, 0x2852, 0x4B2, 0x0C01,
0x1254, 0x296C, 0x4668, 0x3BEF, 0x102D, 0x103E, 0x5E75, 0x4D2A,
0x5D8, 0x42B3, 0x2972, 0x734B, 0x27E6, 0x3B13, 0x3A51, 0x6CAE,
0x2906, 0x4F66, 0x7930, 0x6D3B, 0x7543, 0x155F, 0x303B, 0x4C76,
0x451B, 0x74D, 0x1391, 0x5234, 0x6523, 0x33F9, 0x3425, 0x452E,
0x630A, 0x2FE9, 0x4868, 0x0B0F, 0x7CD0, 0x30C6, 0x33D4, 0x6E5F,
0x3330, 0x3D54, 0x6081, 0x1E14, 0x3B3B, 0x1A96, 0x3775, 0x36B7,
0x1559, 0x6D3B, 0x6A02, 0x0DF8, 0x1A96, 0x657B, 0x2625, 0x6772,
0x1358, 0x1AB6, 0x7912, 0x0E01, 0x1A26]


with open("./ctf/assets/flag_img.png", "rb") as f:
    png_bytes = f.read()

k = 0x42
flag = ""

for i in idxes:
    flag += chr(png_bytes[i] ^ k)

print(flag)
```

## Flag

`DUCTF{d1d_y0u_r43lly_th1nk_y0u_w0uld_g3t_4_fl4g_f0r_pl4y1ng_a_game?_6e927fd2e11abcd4}`

## Open Problem

Guess塗れの静的解析で解いたので、動的解析に関する次のような事が気になっている。もし知見がある人は教えてください。

- smaliをちょっと変えて1ラウンドを1秒にするようなパッチを当ててApktoolでビルドし直してみたが、上手く動いてくれなかった。というわけで上手いパッチ手段が欲しい
- どんな動きをしているか気になるのでエミュレータとデバッガが欲しい

## References

- [Apktool - A tool for reverse engineering 3rd party, closed, binary Android apps.](https://ibotpeaches.github.io/Apktool/)
- [APK decompiler - decompile Android .apk ✓ ONLINE ✓](http://www.javadecompilers.com/apk)

[^1]: 仮にもセキュリティ関連のアクティビティをやっている人間としてどうかと思うのでエミュレータを使ったほうが良いとは思っている

[^2]: もちろんこの問題のものは読んでいない。終了後に探したが、そもそもCTFリポジトリ(それも解説なしソルバのみ)にしか無かった
