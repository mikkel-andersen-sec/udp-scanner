# Build Instructions

## Quick Start

### Standard Version (Original)
```bash
make
sudo ./udp_scanner <target> <start_port> <end_port>
```

### Extended Version (50+ Protocols)
```bash
gcc -Wall -Wextra -O2 -o udp_scanner_extended udp_scanner_extended.c
sudo ./udp_scanner_extended <target> <start_port> <end_port>
```

---

## Compilation Options

### Basic Compilation
```bash
gcc -o udp_scanner udp_scanner.c
```

### Optimized Build
```bash
gcc -O3 -march=native -o udp_scanner udp_scanner.c
```

### Debug Build
```bash
gcc -g -DDEBUG -o udp_scanner_debug udp_scanner.c
```

### Static Build (Portable)
```bash
gcc -static -o udp_scanner_static udp_scanner.c
```

---

## Platform-Specific

### Linux
```bash
gcc -Wall -Wextra -O2 -o udp_scanner udp_scanner.c
```

### macOS
```bash
# May need to adjust ICMP header includes
gcc -Wall -Wextra -O2 -o udp_scanner udp_scanner.c
```

### FreeBSD
```bash
cc -Wall -Wextra -O2 -o udp_scanner udp_scanner.c
```

---

## Using Makefile

### Build
```bash
make          # Compile
make clean    # Remove binaries
```

### Install System-Wide
```bash
sudo make install    # Install to /usr/local/bin
sudo make uninstall  # Remove from system
```

### Update Makefile for Extended Version
Add to Makefile:
```makefile
EXTENDED = udp_scanner_extended

extended: $(EXTENDED)

$(EXTENDED): udp_scanner_extended.c
	$(CC) $(CFLAGS) -o $@ $<

all: $(TARGET) $(EXTENDED)
```

---

## Compiler Warnings

Recommended flags:
```bash
-Wall          # Enable all warnings
-Wextra        # Extra warnings
-Werror        # Treat warnings as errors
-Wpedantic     # ISO C compliance
```

---

## Troubleshooting

### "Permission denied" when running
```bash
# Solution: Run with sudo (needs raw sockets)
sudo ./udp_scanner 127.0.0.1 1 100
```

### "socket: Operation not permitted"
```bash
# Solution: Need CAP_NET_RAW capability
sudo setcap cap_net_raw+ep ./udp_scanner
```

### Compilation errors on macOS
```c
// Add to source before includes:
#ifdef __APPLE__
#define __APPLE_USE_RFC_3542
#include <netinet/in_systm.h>
#endif
```

---

## Dependencies

Required (should be in standard C library):
- `sys/socket.h`
- `netinet/in.h`
- `netinet/ip.h`
- `netinet/ip_icmp.h`
- `arpa/inet.h`

No external libraries needed!

---

## Performance Tuning

### Compiler Optimizations
```bash
# Maximum optimization
gcc -O3 -march=native -flto -o udp_scanner udp_scanner.c
```

### Link-Time Optimization
```bash
gcc -O2 -flto -fuse-linker-plugin -o udp_scanner udp_scanner.c
```

---

## Cross-Compilation

### For ARM (Raspberry Pi)
```bash
arm-linux-gnueabihf-gcc -o udp_scanner_arm udp_scanner.c
```

### For MIPS (Routers)
```bash
mips-linux-gnu-gcc -o udp_scanner_mips udp_scanner.c
```

---

## Size Optimization

### Smallest Binary
```bash
gcc -Os -s -o udp_scanner udp_scanner.c
strip --strip-all udp_scanner
upx --best udp_scanner  # If UPX is installed
```

---

## Docker Build

Create `Dockerfile`:
```dockerfile
FROM gcc:latest
WORKDIR /app
COPY udp_scanner.c .
RUN gcc -O2 -o udp_scanner udp_scanner.c
ENTRYPOINT ["./udp_scanner"]
```

Build and run:
```bash
docker build -t udp-scanner .
docker run --rm --cap-add=NET_RAW udp-scanner 8.8.8.8 53 53
```
