BINARY := portwhat

.PHONY: all build vet test clean

all: build

build:
	go build -o $(BINARY) .

vet:
	go vet ./...

test: vet
	go test -v ./...

clean:
	rm -f $(BINARY)
