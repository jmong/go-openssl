PROG := go-openssl
GO   := $(shell which go)

.PHONY: build clean
build:
	$(GO) build -o build/$(PROG)

rebuild: clean build

clean:
	rm -f build/$(PROG)
