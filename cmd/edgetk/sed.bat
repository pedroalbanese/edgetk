@ECHO OFF

busybox sed "/\/\//d" <main.go |gofmt -s|clip
