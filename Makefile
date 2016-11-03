# This is how we want to name the binary output
BINARY=simple-cloud-encrypt

# These are the values we want to pass for Version and BuildTime
VERSION=0.9.2
#BUILD_TIME=`date +%FT%T%z`

# Setup the -ldflags option for go build here, interpolate the variable values
#LDFLAGS=-ldflags "-X github.com/ariejan/roll/core.Version=${VERSION} -X github.com/ariejan/roll/core.BuildTime=${BUILD_TIME}"

all:
	go build  -o ${BINARY} simple-cloud-encrypt.go

clean:
	rm ${BINARY}

tar:
	mkdir ${BINARY}-${VERSION}
	cp simple-cloud-encrypt.go LICENSE simple-cloud-encrypt.spec ${BINARY}-${VERSION}/
	tar -cvzf simple-cloud-encrypt-${VERSION}.tar.gz ${BINARY}-${VERSION}/
	rm -rf ${BINARY}-${VERSION}/	
