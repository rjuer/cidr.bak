build:
	go build -o bin/cidr

update:
	go mod tidy

.PHONY: build tidy
