module github.com/pedroalbanese/edgetk

go 1.20

require (
	git.sr.ht/~sircmpwn/go-bare v0.0.0-20210406120253-ab86bc2846d9
	gitee.com/Trisia/gotlcp v1.3.17
	github.com/RyuaNerin/elliptic2 v1.0.0
	github.com/RyuaNerin/go-krypto v1.3.0
	github.com/deatil/go-cryptobin v1.0.4018
	github.com/emmansun/certinfo v0.1.0
	github.com/emmansun/gmsm v0.24.2
	github.com/emmansun/go-pkcs12 v0.3.0
	github.com/kasperdi/SPHINCSPLUS-golang v0.0.0-20231223193046-84468b93f7e9
	github.com/pedroalbanese/IGE-go v0.0.0-20140730194654-752bc7fd80fb
	github.com/pedroalbanese/anubis v0.0.1
	github.com/pedroalbanese/bash v0.0.0-20240917213542-359ea9ed86ee
	github.com/pedroalbanese/belt v0.0.0-20240917222837-2f97e6235d6c
	github.com/pedroalbanese/bign v0.0.0-20240918155826-90ccb6b122b9
	github.com/pedroalbanese/bip0340 v0.0.0-20241210175635-d2ef3194b7de
	github.com/pedroalbanese/bmw v0.0.0-20240608175405-99257887a774
	github.com/pedroalbanese/brainpool v0.0.0-20220826183126-be5c94625a31
	github.com/pedroalbanese/camellia v0.0.0-20220911183557-30cc05c20118
	github.com/pedroalbanese/cast256 v0.0.0-20240325185652-e35cf700d5fe
	github.com/pedroalbanese/cast5 v0.0.0-20220924202825-3e5c3c00277c
	github.com/pedroalbanese/ccm v0.0.0-20230716211039-49b744fc07d4
	github.com/pedroalbanese/cfb1 v0.0.1
	github.com/pedroalbanese/cfb8 v0.0.0
	github.com/pedroalbanese/cmac v0.0.0-20210429130952-a58975ec8f4c
	github.com/pedroalbanese/crypto v0.0.0-20230125215802-8b7e99ecbad3
	github.com/pedroalbanese/crypton v0.0.0-20240325185448-da9f3c02e89e
	github.com/pedroalbanese/crystals-go v0.0.0-20240315230756-81011b679705
	github.com/pedroalbanese/cubehash v0.0.0
	github.com/pedroalbanese/cubehash256 v0.0.0-20240403151932-00980243a56a
	github.com/pedroalbanese/curupira1 v0.0.0-gama
	github.com/pedroalbanese/curve448 v0.0.0-20240514173232-895b1c6c93a1
	github.com/pedroalbanese/e2 v0.0.0-20240325185507-eef2e0916dc5
	github.com/pedroalbanese/eax v0.0.0-20240629182935-b915af1b69bb
	github.com/pedroalbanese/ecb v0.0.0-20220918174126-1a696b93ae2b
	github.com/pedroalbanese/ecgdsa v0.0.0-20241210175441-06f3e901c677
	github.com/pedroalbanese/echo v0.0.0-20240329160327-5e65f19de84b
	github.com/pedroalbanese/ecka-eg v0.0.3003
	github.com/pedroalbanese/ecsdsa v0.0.0-20241210175528-7c8b62d098d0
	github.com/pedroalbanese/esch v0.0.0-20240403151441-bc287e464d49
	github.com/pedroalbanese/frp256v1 v0.0.2-0.20240924173051-9a21c6c1586f
	github.com/pedroalbanese/fugue v0.0.0-20240518170253-4e3af93fc75a
	github.com/pedroalbanese/gmac v0.0.0-20231030174635-9eb35b8b4542
	github.com/pedroalbanese/go-ascon v0.0.0-20240325185942-de83d7994a95
	github.com/pedroalbanese/go-chaskey v0.0.0-20230117155006-a9e41c18223c
	github.com/pedroalbanese/go-external-ip v0.0.0-20200601212049-c872357d968e
	github.com/pedroalbanese/go-grain v0.0.0-20240325185755-73b4f13ea6bc
	github.com/pedroalbanese/go-idea v0.0.0-20170306091226-d2fb45a411fb
	github.com/pedroalbanese/go-kcipher2 v0.0.0-20170506094415-4fcf5aa27627
	github.com/pedroalbanese/go-krcrypt v0.0.0-20170928183100-a0c871728ae1
	github.com/pedroalbanese/go-misty1 v0.0.0-20150819220543-a3984aec4fae
	github.com/pedroalbanese/go-nums v0.0.0-20240718212750-f4c240aa5c08
	github.com/pedroalbanese/go-rc5 v0.0.0-20181025211356-a14dd155920a
	github.com/pedroalbanese/go-ripemd v0.0.0-20200326052756-bd1759ad7d10
	github.com/pedroalbanese/gogost v0.0.0-20240430171730-f95129c7a5af
	github.com/pedroalbanese/golang-rc6 v0.0.0-20240204183933-f7014051ac04
	github.com/pedroalbanese/gopass v0.0.0-20210920133722-c8aef6fb66ef
	github.com/pedroalbanese/groestl v1.0.1
	github.com/pedroalbanese/hamsi v0.0.0-20240518170147-c7c58b0f2a86
	github.com/pedroalbanese/haraka v0.0.0-20180824194238-3cf1081eecd7
	github.com/pedroalbanese/jh v0.0.0-20240624180005-e6705e517191
	github.com/pedroalbanese/kalyna v0.0.0-20240325185136-5fa784896340
	github.com/pedroalbanese/khazad v0.0.0-20240325185634-12dbcf5e3eaa
	github.com/pedroalbanese/kupyna v0.0.0-20240326161126-ebb2f9665eeb
	github.com/pedroalbanese/kuznechik v0.0.0
	github.com/pedroalbanese/loki97 v0.0.0-20240325185530-a0580bcacc04
	github.com/pedroalbanese/luffa v0.0.0-20240518171333-cf7dac6a64ae
	github.com/pedroalbanese/lyra2re v0.0.0-20240520232624-5764a75dde63
	github.com/pedroalbanese/lyra2rev2 v0.0.0-20240608181906-fe968f886565
	github.com/pedroalbanese/magenta v0.0.0-20241208214047-a79e5e9ef277
	github.com/pedroalbanese/makwa-go v0.0.0-20240816162209-f803984910a2
	github.com/pedroalbanese/mars v0.0.0-20240325185557-fe8b863ed824
	github.com/pedroalbanese/md6 v0.0.0-20240815222317-052c055905a4
	github.com/pedroalbanese/noekeon v0.0.0-20240325185408-f90c60f5190f
	github.com/pedroalbanese/ocb v0.0.0-20230501153203-7d2a80fe6a75
	github.com/pedroalbanese/ocb3 v0.0.0-20230127113333-c403200ee5a8
	github.com/pedroalbanese/panama v0.0.0-20240325185906-f9d6500cb56b
	github.com/pedroalbanese/pmac v0.0.0-20240715205711-f4d312cbf6c5
	github.com/pedroalbanese/present v0.0.0-20240325185615-de3b5340e616
	github.com/pedroalbanese/rabbitio v0.0.0-20230209212404-cffc97bafde8
	github.com/pedroalbanese/radio_gatun v0.0.0-20240520204859-03d5d3af41c3
	github.com/pedroalbanese/randomart v0.0.0-20130402080559-540116cac932
	github.com/pedroalbanese/rc2 v0.0.0-20131011165748-24b9757f5521
	github.com/pedroalbanese/secp256k1 v0.1.3
	github.com/pedroalbanese/shacal2 v0.0.0-20240911175924-cbeaa118c471
	github.com/pedroalbanese/shavite v0.0.0-20240518173728-5c0c7c528bc7
	github.com/pedroalbanese/simd v0.0.0-20240518173711-b73ebc90aae8
	github.com/pedroalbanese/siphash v1.0.1
	github.com/pedroalbanese/siv v0.0.2
	github.com/pedroalbanese/skein v0.0.0-20230124182825-ffe5e4ff3827
	github.com/pedroalbanese/skein-1 v0.0.0-20171112102903-d7f1022db390
	github.com/pedroalbanese/spritz v0.0.0-20140823220804-e125bc694ec3
	github.com/pedroalbanese/threefish v0.0.0-20230828205611-8dc287bb1622
	github.com/pedroalbanese/tiger v0.0.0-20220128183340-a7e964767a9d
	github.com/pedroalbanese/trivium v0.0.0-20170225064545-3bc0ea456f63
	github.com/pedroalbanese/twine v0.0.0-20240325185833-a027b56be619
	github.com/pedroalbanese/vmac v0.0.0-20231111194716-1a03aacdcb4c
	github.com/pedroalbanese/whirlpool v0.0.0-20220911221330-8ad94dd14447
	github.com/pedroalbanese/xoodoo v0.0.0-20230124190939-64aa038b97c6
	github.com/zeebo/blake3 v0.2.3
	golang.org/x/crypto v0.30.0
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/bwesterb/go-ristretto v1.2.3 // indirect
	github.com/codahale/makwa v0.0.0-20141227225204-3dbfaeed5fdb // indirect
	github.com/klauspost/cpuid/v2 v2.0.12 // indirect
	github.com/nixberg/chacha-rng-go v0.1.0 // indirect
	github.com/pedroalbanese/blake256 v0.0.0-20170713140427-6aca07c5447e // indirect
	github.com/pedroalbanese/bmw256 v0.0.0-20240403151626-135f0d278f9f // indirect
	github.com/pedroalbanese/groestl-1 v0.0.0-20230125170437-46d496027e3d // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/term v0.27.0 // indirect
)
