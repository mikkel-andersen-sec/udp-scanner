# Makefile for UDP Scanner

CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11
LDFLAGS = -lpthread
TARGET = udp_scanner
SOURCES = udp_scanner.c
OBJECTS = $(SOURCES:.c=.o)

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(TARGET) $(OBJECTS)

install: $(TARGET)
	@echo "Installing $(TARGET) to /usr/local/bin (requires sudo)"
	sudo cp $(TARGET) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(TARGET)
	@echo "Installation complete. Run with: sudo $(TARGET)"

uninstall:
	@echo "Removing $(TARGET) from /usr/local/bin"
	sudo rm -f /usr/local/bin/$(TARGET)
	@echo "Uninstallation complete"

help:
	@echo "UDP Scanner Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  all       - Build the scanner (default)"
	@echo "  clean     - Remove build artifacts"
	@echo "  install   - Install to /usr/local/bin (requires sudo)"
	@echo "  uninstall - Remove from /usr/local/bin (requires sudo)"
	@echo "  help      - Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  make"
	@echo "  sudo ./$(TARGET) <target_ip> <start_port> <end_port>"
