all: clean rcfctl

rcfctl:
	CGO_ENABLED=0 go build -o rcfctl main.go

all-arch:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o rcfctl-amd64 main.go
	GOOS=linux GOARCH=arm CGO_ENABLED=0 go build -o rcfctl-arm main.go
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o rcfctl-arm64 main.go
	GOOS=linux GOARCH=mips CGO_ENABLED=0 go build -o rcfctl-mips main.go
	GOOS=linux GOARCH=mips64 CGO_ENABLED=0 go build -o rcfctl-mips64 main.go
	GOOS=linux GOARCH=riscv64 CGO_ENABLED=0 go build -o rcfctl-riscv64 main.go
	GOOS=linux GOARCH=ppc64 CGO_ENABLED=0 go build -o rcfctl-ppc64 main.go
	GOOS=linux GOARCH=ppc64le CGO_ENABLED=0 go build -o rcfctl-ppc64le main.go
	GOOS=linux GOARCH=s390x CGO_ENABLED=0 go build -o rcfctl-s390x main.go

install:
	mv rcfctl /usr/bin
	cp systemd/roscaelum.service /etc/systemd/system/
	cp config.default.yml /etc/roscaelum.yml
	systemctl daemon-reload

clean:
	rm -f rcfctl rcfctl-amd64 rcfctl-arm rcfctl-arm64 rcfctl-mips rcfctl-mips64 rcfctl-riscv64 rcfctl-ppc64 rcfctl-ppc64le rcfctl-s390x
