module examples

go 1.24.0

toolchain go1.24.1

require (
	github.com/84codes/sparoid.go v0.0.0-20231013090140-d5714c7c4e84
	github.com/joho/godotenv v1.5.1
	golang.org/x/crypto v0.45.0
)

require golang.org/x/sys v0.38.0 // indirect

replace github.com/84codes/sparoid.go => ../
