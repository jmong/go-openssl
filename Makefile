PROG := learn-by-demo-ssl
GO   := $(shell which go)

.PHONY: build clean
build:
	$(GO) build -o build/$(PROG) main.go

rebuild: clean build

clean:
	rm -f build/$(PROG)
