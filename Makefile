PROG := learn-by-demo-ssl
GO   := $(shell which go)

.PHONY: build clean
build:
	$(GO) build -o build/$(PROG) main.go

clean:
	rm -f build/$(PROG)
