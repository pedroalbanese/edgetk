module github.com/pedroalbanese/edgetk

go 1.17

require (
	github.com/RyuaNerin/go-krypto v1.0.2
	github.com/emmansun/certinfo v0.1.0
	github.com/emmansun/gmsm v0.14.1
	github.com/pedroalbanese/anubis v0.0.0-gama
	github.com/pedroalbanese/camellia v0.0.0-20220911183557-30cc05c20118
	github.com/pedroalbanese/cast5 v0.0.0-20220924202825-3e5c3c00277c
	github.com/pedroalbanese/cfb8 v0.0.0
	github.com/pedroalbanese/cmac v0.0.0-20210429130952-a58975ec8f4c
	github.com/pedroalbanese/go-external-ip v0.0.0-20200601212049-c872357d968e
	github.com/pedroalbanese/go-idea v0.0.0-20170306091226-d2fb45a411fb
	github.com/pedroalbanese/go-krcrypt v0.0.0-20170928183100-a0c871728ae1
	github.com/pedroalbanese/go-rc5 v0.0.0-20181025211356-a14dd155920a
	github.com/pedroalbanese/gogost v0.0.0-20220417104440-4d34dbc5957c
	github.com/pedroalbanese/kuznechik v0.0.0
	github.com/pedroalbanese/rc2 v0.0.0-20131011165748-24b9757f5521
	github.com/pedroalbanese/whirlpool v0.0.0-20220911221330-8ad94dd14447
	golang.org/x/crypto v0.0.0-20220924013350-4ba4fb4dd9e7
	golang.org/x/sys v0.0.0-20220919091848-fb04ddd9f9c8 // indirect
)

require github.com/pedroalbanese/randomart v0.0.0-20130402080559-540116cac932

require github.com/pkg/errors v0.9.1 // indirect

exclude (
	github.com/pedroalbanese/edgetk/ccm v0.0.0-20220123113355-35f3430b3606
	github.com/pedroalbanese/edgetk/cfb8 v0.0.0-20220525222753-53024fb2aa30
	github.com/pedroalbanese/edgetk/eax v0.0.0-20220123113355-35f3430b3606
	github.com/pedroalbanese/edgetk/ecb v0.0.0-20220506170819-de27054afdf0
	github.com/pedroalbanese/edgetk/groestl v0.0.0-20220123113355-35f3430b3606
	github.com/pedroalbanese/edgetk/jh v0.0.0-20220123113355-35f3430b3606
	github.com/pedroalbanese/edgetk/ocb v0.0.0-20220123113355-35f3430b3606
	github.com/pedroalbanese/edgetk/pragma v0.0.0-20220126184759-2301e1720152
	github.com/pedroalbanese/edgetk/threefish v0.0.0-20220123113355-35f3430b3606
	github.com/pedroalbanese/edgetk/scrypt v0.0.0-20211221223835-ba79f7054455
	github.com/pedroalbanese/edgetk/scrypt2 v0.0.0-20211221224834-8a3d70a15230
	github.com/pedroalbanese/edgetk/c509 v0.0.0-20211124163654-e3b6c40b8f01
)
