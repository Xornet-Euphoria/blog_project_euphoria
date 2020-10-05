+++
title = "Teraテンプレートについてとその改造(数式対応)"
date = 2020-10-05

[taxonomies]
categories = ["zola"]
tags = ["zola", "Tera", "KaTeX"]
+++

[前回のエントリ](@/1_hello_zola.md)でも述べているようにafter-darkを採用した。[Githubリポジトリ](https://github.com/getzola/after-dark)のREADMEに書いてある通りにやればだいたい動くが、後で忘れないように詰まりかけたところはメモしておく。
<!-- more -->

### `contents/_index.md`の前付を書く

```markdown
+++
paginate_by = <number>
+++
```

を書いておく必要がある。`+++`の後には改行が必要(Githubで他のリポジトリの`_index.md`を参考にして"プレビュー"からコピペすると空白になっているのに引っかかった)。

### indexにおけるsummarize

記事中に`<!-- more -->`を記述することでそこまでの内容を記事一覧で表示することが出来る。

### 数式対応

after-darkは最初から数式対応しているわけではない。別テーマである[evenの数式対応コミット](https://github.com/getzola/even/commit/767b0663c1d7b57ba4824acfd57be65a48e35e0d)を参考にしてテンプレートを改造した。

やっていることはCDNからkatexのjsとCSSのリンクを引っ張って貼っつけてるだけである。shortcodeを利用しているためそれ用のフォルダを生成する必要がある。

個人的にはHackMDで慣れてしまったこともあり、`$$ \kaTeX $$`のような書き方が出来るauto-render拡張が欲しかった。これだけで次のように数式を表示させることが出来る。
$$ \KaTeX $$

## 今後の予定

数式対応したので特に無い。気が向いたら配色やタグ、カテゴリーの表記とか変えるかもしれない。

SNS共有ボタンの実装も考えたが、今の所私の技術系記事が他で共有された例を知らないのでひとまず優先順位は下げておく。

書いてて思い出した、Aboutページは作るかもしれない。

## 参考文献

* [Zola入門](https://brainvader.github.io/brain-space/blog/2019/05/post-038/)
