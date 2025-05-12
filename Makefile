# Define the target binary name
BINARY_NAME := netmon

# Default target: build the binary
all: clean $(BINARY_NAME)

# Compile the Go program with CGO_ENABLED=1 for static linking
$(BINARY_NAME):
	CGO_ENABLED=1 go build -o netmon main.go
	go build -o $(BINARY_NAME) main.go

# Clean up the build (remove the binary)
clean:
	rm -f $(BINARY_NAME)

# Phony targets to avoid conflict with files named 'clean' or 'all'
.PHONY: all clean

