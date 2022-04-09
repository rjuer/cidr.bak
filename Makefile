build:
	go build -o out/cidr

update:
	go mod tidy

.PHONY: build tidy
