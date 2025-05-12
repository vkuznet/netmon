all: netmon

netmon:
	CGO_ENABLED=1 go build -o netmon main.go

clean:
	rm -f netmon
