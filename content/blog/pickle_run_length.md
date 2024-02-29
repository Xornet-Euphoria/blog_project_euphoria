+++
title = "Pickleでランレングス圧縮をやる"
date = 2024-02-29

[taxonomies]
tags = ["pickle"]
+++

## まえがき

Pythonでオブジェクトをシリアライズする手段としてPickleが知られている。こいつはスタックマシンを実行する形でデータを構築していくという設計をしている上に内部でPythonの関数を呼べるため、一部のCTFプレイヤーのおもちゃとして遊ばれることがある。出題形式として、[Pickleでフラグチェッカーを書いてRevで出したり](https://github.com/acsc-org/acsc-challenges-2021-public/tree/main/rev/Pickle_Rick)、[制約の下でRCEをすることを求めてMisc/Pwnで出されたりする](https://blog.splitline.tw/hitcon-ctf-2022/#%F0%9F%A5%92-picklection-misc)ことがあり、前者のRevに関しては私も[SECCON 2023で出題](https://github.com/SECCON/SECCON2023_online_CTF/tree/main/reversing/Sickle)している。

最近またﾊﾟｿｶﾀのやる気を取り戻した私だが、以前同様慢性的なネタ不足に苦しめられており、Pickleに関しては前述のSECCONにおける出題以降、特にアイデアが出ていなかった。そんな中、Pickleとは関係ない問題のペイロードを(長さ制限もないのに)削減するという経験をした結果、Pickleのバイトコードを普通にシリアライズするより短くするというアイデアが生じたのでひとまず簡単なランレングス圧縮を実現することにした。

## 速習: Pickle

まえがきにも書いたようにPickleはバイト列をデシリアライズする際に、バイトコードをスタックマシンで処理するような手順を取る。

例えば、数値の1をシリアライズした場合、(本質的な部分だけを抽出すると)`b'I1\n'`という3バイトのバイト列に変換される。このバイト列の先頭の`I`は`INT`というバイトコードに相当し、続くバイト列から改行まで読み込んだ結果を`int`に渡した結果がスタックにpushされる。Pythonにはpickletoolsというモジュールが存在して、これの`dis`関数は与えたバイト列を逆アセンブルしてくれるので実際にこれに与えてみると次のようになる(pickleの終端を示す`pickle.STOP`が無いと怒られるので末尾に付けている)。

```txt
$ python
Python 3.12.0 (main, Nov 17 2023, 10:53:33) [GCC 11.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import pickletools
>>> import pickle
>>> pickletools.dis(b'I1\n' + pickle.STOP)
    0: I    INT        1
    3: .    STOP
highest protocol among opcodes = 0
>>> 
```

このようにしてPickleは与えられたバイト列を順に読み込みながらバイトコードとして解釈してスタック上にオブジェクトを構築していき、最終的に`pickle.STOP`が呼ばれた際にスタックトップにあるものがデシリアライズ結果として返ってくる。

バイトコードの一覧とその実装は[cpython/Lib/pickle.py at main · python/cpython · GitHub](https://github.com/python/cpython/blob/main/Lib/pickle.py)を見ると全部乗っており、バイトコードと実装は`load_<bytecode>`という形のメソッドに対応する。内部では[Cで書かれたもの](https://github.com/python/cpython/blob/main/Modules/_pickle.c)をimportしているため、稀に想定通りの動きをしないことがある[^1]が基本的にはここを読めば問題ない。

ここで面白いのがREDUCEというバイトコードである。これに対応するメソッドは[`load_reduce`](https://github.com/python/cpython/blob/02beb9f0208d22fd8bd893e6e6ec813f7e51b235/Lib/pickle.py#L1580C1-L1585C38)であり、次のような実装になっている。

```python
    def load_reduce(self):
        stack = self.stack
        args = stack.pop()
        func = stack[-1]
        stack[-1] = func(*args)
    dispatch[REDUCE[0]] = load_reduce
```

スタックから引数(のタプル、または配列)と関数をpopして呼び出すという(どう考えても危険な)実装になっており、「Pickleで信頼できないデータをデシリアライズするな」と言われる主な原因はこれである。Pickleには他にも[GLOBAL](https://github.com/python/cpython/blob/e72576c48b8be1e4f22c2f387f9769efa073c5be/Lib/pickle.py#L1520C1-L1525C38)というバイトコードが存在していて、詳しくはその内部で使われている[`find_class`メソッド](https://github.com/python/cpython/blob/e72576c48b8be1e4f22c2f387f9769efa073c5be/Lib/pickle.py#L1566)を参照して頂きたいが、実質的にモジュールから関数を含めたオブジェクトをimportすることが出来る。これを組み合わせるとPython中で使える任意の関数を呼ぶことが可能になる。試しに[Pickleのドキュメント](https://docs.python.org/ja/3/library/pickle.html#restricting-globals)に乗っている例を`pickletools.dis`で逆アセンブルしてみる。

```txt
>>> pickletools.dis(b"cos\nsystem\n(S'echo hello world'\ntR.")
    0: c    GLOBAL     'os system'
   11: (    MARK
   12: S        STRING     'echo hello world'
   32: t        TUPLE      (MARK at 11)
   33: R    REDUCE
   34: .    STOP
```

GLOBALバイトコードで`os.system`をスタックにpushし、続いてコマンド文字列である`'echo hello world'`をタプルに入れてpushし、REDUCEバイトコードで`os.system('echo hello world')`を実行するという例になっている。

いつもであればこの機能はRCEのために使うが、今回は悪いことをせずにシリアライズ結果のバイト列の削減に使えないかを考える。

## ルール

- 要素が全てintのリストを圧縮対象とする
- ランレングス圧縮が有効な配列が与えられた際に`pickle.dumps`でシリアライズするより短いバイト列を生成する
	- ランレングス圧縮が有効であることの厳密な定義は与えないが、同一要素が最低でも0x10個は連続している配列を与える
- 生成したバイト列を`pickle.loads`でデシリアライズした際に圧縮対象と等価なオブジェクト(ここではintのリスト)が返る
- eval, exec, compileをREDUCEで実行するのは禁止
	- 実は他にも禁止にした方が良さそうな関数はある[^2]が、この3つはダイレクトにPythonのコードゴルフに繋がる可能性があるため真っ先に禁止した
- モジュールのimportはCPythonに含まれているものであれば特に制限しないが、サードパーティのものを使うのは禁止
	- そもそも`from mylib import target`と同様のことをされたら終わる

## コンセプト

Pickleのバイトコードはifやforのような制御構文が無い[^3]だけで基本的にはPythonとほぼ同じことが実現出来る。そこでまずは通常のPythonにおいて比較的短いコードで実現することを目指す。

例として`[1,1,1,1,1,2,2,2,2,3,3,3]`という配列を圧縮することを考える。要素とその連続する数というフォーマットで素直にランレングス圧縮をすると`[(1,5), (2,4), (3,3)]`のような形となる。

逆にこのフォーマットの配列が与えられた時に元の配列に戻す短くて簡単な方法を考える。前述したようにPickleでは組み込みの関数は使えるものの、forを使うことが難しいため、組み込みの関数で簡単に実現したい。

`(1,5)`というタプルから`[1,1,1,1,1]`は`[1] * 5`によって作ることが出来る。Pickleのバイトコード中で`[1]`のような配列は特に工夫せずとも出来るので`getattr([1], "__mul__")(5)`をREDUCEを用いて実行すれば`[1,1,1,1,1]`が手に入る。これで`[1,1,1,1,1], [2,2,2,2], [3,3,3]`はスタック上に乗せることが出来る。

あとは、これらの配列を結合するだけである。真っ先に思いつく方法として、各配列から`__add__`を引っ張ってきたり、`list.__add__()`を引っ張ってくる等で`[1,1,1,1,1] + [2,2,2,2] + [3,3,3]`相当のことを実現することが考えられる。おそらくこれも普通にやるよりは短くなりそうではあるが、配列の数だけ`__add__`メソッドを呼ばなくてはならないため、もう少し短くなる方法を考えたい。ここで、Python組み込み関数の`sum`に配列の配列を渡すと含まれる配列を結合してくれるため、これを利用する。

具体的には`sum([[2,2,2,2], [3,3,3]], [1,1,1,1,1])`を実行する。`sum`の第2引数は初期値を指定するため、このコードは`sum([[1,1,1,1,1], [2,2,2,2], [3,3,3]], [])`と等価であるが、空配列をスタックにpushする分のバイトコード(1バイト)をケチっている[^4]。

以上をまとめると、`sum([getattr([2], "__mul__")(4), getattr([3], "__mul__")(3)], getattr([1], "__mul__")(5))`をバイトコードを用いて実行することが今回の目標になる。

## Pickleに関連する最適化

既に`sum`の第2引数を指定するような最適化を例にとったが、Pickleの仕様を利用した最適化についても検討する。

Pickleのバイトコードで実行したいPythonのコードを見ると、`getattr`と`"__mul__"`が複数回出現している。これを都度スタックに積もうとすると、バイトコードの引数に文字列をそのまま与える必要があるため、その分のバイト長が毎度必要になる。これは何も今回に限った話ではなく通常の使用でも問題となることであり、その解決策としてPickleにはメモという機能が存在する。

これは名前の通り、オブジェクトをメモに入れて再利用出来るようにしたもので、MEMOIZEやPUTのようなバイトコードを用いるとスタックトップにあるオブジェクトがメモに格納される(popはされない)。このようにして格納されたオブジェクトはGETのようなバイトコードを用いるとインデックスを指定してオブジェクトをスタックにpushされる。したがってよく使うオブジェクトはメモに入れておいて後で使うようにすれば、バイトコード中に文字列をハードコードして長さが増えることを回避出来る。

実際に`["asdf"] * 10`のような同一要素が並ぶ配列を普通にシリアライズしてみると次のようなバイト列が得られる。

```text
$ python
Python 3.12.0 (main, Nov 17 2023, 01:38:55) [GCC 11.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import pickle
>>> l = ["asdf"] * 10
>>> import pickletools
>>> pickletools.dis(pickle.dumps(l))
    0: \x80 PROTO      4
    2: \x95 FRAME      30
   11: ]    EMPTY_LIST
   12: \x94 MEMOIZE    (as 0)
   13: (    MARK
   14: \x8c     SHORT_BINUNICODE 'asdf'
   20: \x94     MEMOIZE    (as 1)
   21: h        BINGET     1
   23: h        BINGET     1
   25: h        BINGET     1
   27: h        BINGET     1
   29: h        BINGET     1
   31: h        BINGET     1
   33: h        BINGET     1
   35: h        BINGET     1
   37: h        BINGET     1
   39: e        APPENDS    (MARK at 13)
   40: .    STOP
highest protocol among opcodes = 4
>>> 
```

インデックス20で`MEMOIZE`を用いて文字列`"asdf"`をメモに送っており、以後は`BINGET 1`という形でメモを参照してスタックにpushしている。

## PoC

自作のハンドアセンブラ(WIP)を使っているので、それも一緒に載せています。気が向いたらライブラリにしてリポジトリを上げますが期待しないでください。

<script src="https://gist.github.com/Xornet-Euphoria/0691ebe626ed1f6dfcc24884fde59e41.js"></script>

gistに貼ったやつを埋め込んでいるが見栄えが妙に悪いのでそのうち(ブログのデザインを)なんとかします。

## 検証

ランレングス圧縮はその仕組から、連続する要素が存在していないと効果が発揮されない。この手法では内部で`getattr`や`__mul__`をスタックに乗せることと実行にバイトコードを割いているので、それに値するぐらい連続部分が長い配列でないとむしろ普通にシリアライズするより長くなってしまう。というわけで、`[1] * n`という配列はどの`n`以上で普通にシリアライズするより短くなるのかを調べる。

単純に要素数を増やして通常のシリアライズと次のような関数を定義して実行する。

```python
def search_boundary_list():
    for i in range(1, 256):
        target = [1] * i
        org_p = pickle.dumps(target)
        crafter = RunLengthCrafter()
        optimized_p = crafter.create_single_element_list(1, i).get_payload(check_stop=True)

        assert pickle.loads(org_p) == pickle.loads(optimized_p)
        if (l1 := len(optimized_p), l2 := len(org_p)) and l1 < l2:
            print(f"boundary length: {i}")
            print(f"- org: {l2}")
            print(f"- opt: {l1}")

            break
```

実行結果は次の通りで12以上連続する要素があれば短縮可能なことがわかる。

```text
$ python list_maker.py 
boundary length: 12
- org: 40
- opt: 39
```

## あとがき

今回は(実装がクソ簡単だという理由で)ランレングス圧縮に絞って実装したが、Pythonの関数をPickle経由で呼ぶことで愚直なデータの構築をスキップするというのがコンセプトなので、割と色々な遊び方が出来るんじゃないかと思っている。

一方、実用性の面では最近流行りのAIにおいてはモデルを読み込む際に内部でPickleをデシリアライズしていることがあって使えそうに見えて、流石に危険であることを認識しているのか基本的に関数が呼べない(`find_class`メソッドでチェックされて弾かれる)ため、多分訳に立たない予感がする。

もし何かの間違いでPickleの削減を迫られて何かの間違いでこの記事に辿り着いて何かの間違いで圧縮に成功した事例があったら教えて下さい。

## 募集中

- 本記事より短く出来る方法
	- `list.__mul__(arr, n)`をメモに入れて再利用すれば、`getattr`を呼び出す部分が削減出来て要素が多様な配列だと短くなる予感がする
	- `GLOBAL`で`"builtins"`という文字列を2回使っているが、`GLOBAL`をスタックからモジュールの文字列と要素の文字列をpopして同じことをする関数があるのでメモに送って参照したら多分短くなる
	- などなど
- Pickleで変なことをするアイデア
	- ゴルフ以外も募集しています

---

[^1]: 例えば、空の辞書がスタックからpopされることを想定して`if dictionary:`のような書き方になっており、Pythonコード上ではfalseや0を与えても通るように見えるが、C側を見ると辞書かどうかのチェックをしている、といったケースがある (`load_build`で遭遇)

[^2]: 例えば、pickleのスタックマシン内でも`pickle.loads`は使えるので`pickle.loads(lzma.decompress(compressed_payload))`のようなことをスタックマシン内で行えば圧縮ペイロードとコード実行分の長さだけで圧縮を実現出来て面白さがなくなる

[^3]: ものすごく手間をかけると出来て、SECCON 2023で出題した問題はそれを実装した

[^4]: ちなみに`sum`の第2引数のデフォルト値は0でintの配列を足し合わせることを想定しているので、何らかの配列を指定せずに1引数で呼び出すとTypeErrorを吐かれる
