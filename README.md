# Advanced Load Balancer (ADLB)

[![Language](https://img.shields.io/badge/Language-C11-00599C.svg)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey.svg)](#system-requirements)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Architecture](https://img.shields.io/badge/Architecture-Epoll%20%2F%20Kqueue%20Worker%20Pool-orange.svg)](#system-architecture)
[![Concurrency](https://img.shields.io/badge/Concurrency-Lock--Free%20MPSC-brightgreen.svg)](#load-balancing-algorithms)
[![Tests](https://img.shields.io/badge/Tests-33%20Passed-success.svg)](#automated-test-suite-make-test)

**Advanced Load Balancer (ADLB)** is a high-performance, low-latency network load balancer for **Layer 4 (TCP / UDP)** and **Layer 7 (HTTP / HTTPS)** traffic, engineered in modern **C11** with a modular library architecture, non-blocking **epoll / kqueue** worker pools, **lock-free** backend routing, and constant-memory asynchronous logging.

It features **SSL/TLS offloading**, full **HAProxy PROXY Protocol v1** support (both client ingress and upstream egress), proactive **L4/L7 health checks**, an in-flight **Circuit Breaker**, a full-screen interactive **Ncurses terminal dashboard (TUI)**, and an integrated multithreaded benchmarking and stress-testing client (`test_client`).

---

## Table of Contents

1. [System Architecture](#system-architecture)
2. [Key Features](#key-features)
3. [System Requirements](#system-requirements)
4. [Compilation and Build](#compilation-and-build)
5. [Usage Guide and CLI Reference](#usage-guide-and-cli-reference)
6. [Load Balancing Algorithms](#load-balancing-algorithms)
7. [Health Checking and Circuit Breaker](#health-checking-and-circuit-breaker)
8. [Interactive TUI Dashboard](#interactive-tui-dashboard)
9. [Load Testing and Benchmarks (`test_client`)](#load-testing-and-benchmarks-test_client)
10. [Automated Test Suite (`make test`)](#automated-test-suite-make-test)
11. [Security Hardening](#security-hardening)
12. [Repository Structure](#repository-structure)
13. [License](#license)

---

## System Architecture

ADLB is designed around a modular architecture that cleanly separates network I/O primitives from load-balancing engine logic:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   advanced_load_balancer (app/main.c)                  │
├────────────────────────────────────────────────────────────────────────┤
│                     libadvlb (Load Balancer Engine)                    │
│  ┌───────────────────────┬──────────────────────┬────────────────────┐ │
│  │   Epoll Worker Pool   │ Lock-Free Balancer   │ Active HealthCheck │ │
│  │  (Event-Loop N-Thread)│ (RR, LC, WRR, Hash)  │ (TCP / HTTP / Ping)│ │
│  ├───────────────────────┴──────────────────────┴────────────────────┤ │
│  │    Lock-Free MPSC Async Logger    │    Interactive Ncurses TUI    │ │
│  │    (4096-Slot Vyukov Ring Buffer) │    (Real-Time Performance)    │ │
│  └───────────────────────────────────┴───────────────────────────────┘ │
├────────────────────────────────────────────────────────────────────────┤
│                      libadvnet (Network Core & I/O)                    │
│  ┌───────────────────────┬──────────────────────┬────────────────────┐ │
│  │ Linux epoll / macOS   │ Non-blocking Stream  │  PROXY Protocol v1 │ │
│  │ kqueue Compatibility  │  Buffer & Sockets    │  (Decoder/Encoder) │ │
│  └───────────────────────┴──────────────────────┴────────────────────┘ │
└────────────────────────────────────────────────────────────────────────┘
```

- **`libadvnet`**: Cross-platform asynchronous networking core. Translates Linux `epoll` semantics directly to macOS/BSD `kqueue` with unified read/write filter management. Provides RFC-compliant PROXY Protocol v1 parsers and serializers.
- **`libadvlb`**: Core load-balancing engine. Implements the worker thread pool, lock-free routing algorithms, active health checking, 100% non-blocking backend connection handling, circuit breakers, MPSC log drain worker, and Ncurses TUI.
- **`app`**: Main executable entry point, CLI parser, kernel limit manager (`RLIMIT_NOFILE`), and UNIX signal orchestrator.
- **`tools`**: High-concurrency benchmark harness (`test_client` in native C11) and multi-threaded HTTP test servers (`tools/mock_server.py`).
- **`tests`**: Automated unit and integration test harness (`test_suite.c`).

---

## Key Features

- **Epoll / Kqueue Worker Thread Pool**: Replaces legacy blocking "thread-per-connection" designs with $N$ independent event loops matching CPU cores. Each worker maintains an $O(1)$ socket-to-connection table and bidirectional streaming ring buffers with automatic backpressure.
- **100% Non-Blocking Asynchronous Backend Connect**: Eliminates worker thread stalls. Upstream connections are initiated non-blockingly via `EINPROGRESS` and monitored through epoll/kqueue for `EPOLLOUT`. Ingress client payloads are buffered in pipelined buffers and immediately forwarded upon socket establishment.
- **Lock-Free Routing Algorithms**: Algorithms such as Round-Robin, Least-Connections, IP-Hash, Least-Latency, and Random-2 select backends and update active metric counters without acquiring any global mutexes, relying strictly on C11 atomic operations (`atomic_fetch_add_explicit`).
- **Lock-Free MPSC Async Logging**: `add_log()` formats messages and enqueues them into a 4096-slot lock-free multi-producer single-consumer ring buffer in nanoseconds. A dedicated background worker thread flushes logs to standard output or the TUI buffer without adding latency to network workers.
- **Modern SSL/TLS Offloading**: High-throughput TLS termination via OpenSSL supporting modern ciphersuites (TLS 1.2 / TLS 1.3), non-blocking asynchronous handshakes, and side-channel attack protection.
- **PROXY Protocol v1 Support (RFC-Compliant)**:
  - Header transmission (`--proxy-protocol`) to upstream backends to preserve original client IP addresses.
  - Ingress decoding (`--accept-proxy`) from upstream reverse proxies or CDNs (e.g., AWS ALB, Cloudflare, HAProxy).
- **Real-Time Interactive TUI Dashboard**: Full-screen Ncurses terminal interface refreshed at 10 Hz with color-coded backend health statuses (UP/DOWN indicators), millisecond RTT latency tracking, request counters, active connection meters, and an integrated scrolling log pane.

---

## System Requirements

### Supported Operating Systems
- **Linux**: Kernel 3.10+ (native `epoll` and `SO_REUSEPORT`).
- **macOS**: OS X 10.12+ / macOS Sonoma / Sequoia (native `kqueue` abstraction layer).

### Build Dependencies
- C11-compliant compiler: `gcc` (v7+) or `clang` (v10+).
- GNU Make (`make`).
- **OpenSSL** library (`libssl-dev` / `openssl@3` / `openssl@4`) for TLS offloading.
- **Ncurses** library (`libncurses-dev` / `ncurses`) for the interactive console.

#### Installing Dependencies on Ubuntu / Debian:
```bash
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev libncurses5-dev libncursesw5-dev
```

#### Installing Dependencies on macOS (Homebrew):
```bash
brew install openssl ncurses
```

---

## Compilation and Build

The repository includes a hierarchical Makefile supporting multiple configurations:

### 1. Standard Full Build (Recommended)
Builds `libadvnet`, `libadvlb`, the main `advanced_load_balancer` daemon, and `test_client`:
```bash
make
```

### 2. Pure Layer 4 Build without SSL (`make nossl`)
Ideal for embedded devices, routers, or environments where OpenSSL is unavailable:
```bash
make nossl
```

### 3. Debug Build with Sanitizers (`make debug`)
Enables AddressSanitizer (`-fsanitize=address`) and UndefinedBehaviorSanitizer (`-fsanitize=undefined`) with debug symbols (`-g -O0`):
```bash
make debug
```

### 4. Running the Automated Test Suite (`make test`)
Compiles and executes all 33 unit and integration tests with instant colored output:
```bash
make test
```

### 5. Build Only the Test Client
```bash
make client
```

### 6. Clean All Build Artifacts
```bash
make clean
```

---

## Usage Guide and CLI Reference

```
Usage:
  ./advanced_load_balancer -p PORT -b IP:PORT[:WEIGHT] [OPTIONS]
```

### Mandatory Arguments
| Option | Description |
| :--- | :--- |
| `-p, --port PORT` | Ingress listening port for TCP or UDP traffic (1-65535). |
| `-b, --backend IP:PORT[:W]` | Upstream backend server with optional weight (default: 1). Can be repeated or passed as a comma-separated list. |

### Routing Algorithms
| Option | Description |
| :--- | :--- |
| `--algo NAME` | Selects load-balancing algorithm (`rr`, `lc`, `ip-hash`, `latency`, `wrr`, `random`). |
| `--rr` | Sequential Round-Robin (lock-free). |
| `--lc` | Least-Connections: routes to backend with fewest active connections (lock-free, default). |
| `--ip-hash` | Client IP Hash: deterministic session affinity per client IP (lock-free). |
| `--latency` | Least-Latency: routes to backend with lowest measured RTT (lock-free). |
| `--wrr` | Smooth Weighted Round-Robin (smooth traffic distribution proportional to assigned weights). |
| `--random` | Power of Two Choices: samples 2 random nodes and chooses the least loaded (lock-free). |

### SSL / TLS Offloading (HTTPS Termination)
| Option | Description |
| :--- | :--- |
| `-s, --ssl` | Enables TLS termination for HTTPS / secure WebSockets. |
| `--cert FILE` | Path to public X.509 certificate file (`server.crt`). Required with `--ssl`. |
| `--key FILE` | Path to private RSA/ECC key file (`server.key`). Required with `--ssl`. |

### PROXY Protocol v1
| Option | Description |
| :--- | :--- |
| `-P, --proxy-protocol` | Prepend HAProxy PROXY Protocol v1 header when connecting to backends. |
| `--accept-proxy` | Parse and decode PROXY Protocol v1 header received from upstream load balancers. |

### Layer 4 UDP Mode
| Option | Description |
| :--- | :--- |
| `-u, --udp` | Enables Layer 4 UDP datagram load balancing (default: TCP streaming). |
| `--udp-timeout SEC` | Inactivity expiration timeout for UDP NAT sessions in seconds (default: 30). |

### Health Check and Circuit Breaker
| Option | Description |
| :--- | :--- |
| `--hc-type TYPE` | Probe type: `tcp` (default), `http`, or `payload`. |
| `--http-hc` | Enable Layer 7 HTTP health probes (shortcut for `--hc-type http`). |
| `--hc-path PATH` | HTTP URI path for health check probe (default: `/`). |
| `--hc-send STR` | Custom string sent in application payload probe (default: `PING\r\n`). |
| `--hc-expect STR` | Expected substring in backend probe response (default: `PONG`). |
| `--hc-interval SEC` | Interval between consecutive active health checks in seconds (default: 2). |
| `--hc-timeout MS` | Response timeout for health check probe in milliseconds (default: 800). |

### Performance and Worker Tuning
| Option | Description |
| :--- | :--- |
| `-w, --workers NUM` | Number of epoll/kqueue worker threads (default: CPU cores, clamped 1-256). |
| `-m, --max-connections NUM` | Maximum simultaneous concurrent client connections before dropping (default: 4096). |
| `--timeout SEC` | Inactivity timeout for client streaming sockets in seconds (default: 30). |
| `--no-tui` | Disable interactive Ncurses TUI and print logs directly to standard output. |

---

## Usage Examples

### Example 1: Standard HTTP Load Balancing with Round-Robin
```bash
./advanced_load_balancer -p 8080 -b 127.0.0.1:9001,127.0.0.1:9002,127.0.0.1:9003 --rr
```

### Example 2: High-Performance HTTPS / SSL Termination
```bash
./advanced_load_balancer -p 8443 --ssl --cert certs/server.crt --key certs/server.key \
    -b 127.0.0.1:9001 -b 127.0.0.1:9002 --lc --no-tui
```

### Example 3: Weighted Round-Robin with Active HTTP Health Checking
```bash
./advanced_load_balancer -p 8080 \
    -b 10.0.0.1:80:3 -b 10.0.0.2:80:1 \
    --algo wrr --http-hc --hc-path /healthz --hc-interval 1
```

### Example 4: Layer 4 UDP Balancer (DNS or Real-Time Gaming)
```bash
./advanced_load_balancer -p 53 -u -b 1.1.1.1:53 -b 8.8.8.8:53 --udp-timeout 10
```

---

## Load Balancing Algorithms

ADLB provides optimized algorithms suited for diverse deployment architectures:

```
┌─────────────────────────┬──────────────────────┬────────────────────────────────────────┐
│ Algorithm               │ Concurrency Model    │ Distribution Behavior                  │
├─────────────────────────┼──────────────────────┼────────────────────────────────────────┤
│ Round-Robin (rr)        │ Lock-Free (Atomic)   │ Strict 1:1 cyclic rotation             │
│ Least-Connections (lc)  │ Lock-Free (Atomic)   │ Routes to node with lowest load        │
│ Client IP-Hash          │ Lock-Free (Atomic)   │ Deterministic affinity via IP hashing  │
│ Least-Latency           │ Lock-Free (Atomic)   │ Routes to node with minimum RTT latency│
│ Random 2 Choices        │ Lock-Free (Atomic)   │ Samples 2 random nodes, picks minimum  │
│ Smooth Weighted RR      │ Mutex-Protected      │ NGINX-style smooth weighted selection  │
└─────────────────────────┴──────────────────────┴────────────────────────────────────────┘
```

---

## Health Checking and Circuit Breaker

ADLB protects upstream infrastructure through dual-tier cooperative health monitoring:

1. **Active Prober Thread**:
   - Executes periodic asynchronous socket probes (`tcp`, `http`, or `payload`).
   - Fall Threshold: **3 consecutive failures** (`FALL_THRESHOLD`) transitions a node to `DOWN`.
   - Rise Threshold: **2 consecutive successes** (`RISE_THRESHOLD`) restores a node back to `UP`.
2. **In-Flight Circuit Breaker**:
   - When active client traffic fails to connect or an upstream backend drops connections, `record_backend_failure()` increments error metrics.
   - To safeguard against premature drops during transient burst spikes, client connection errors use a threshold of 20 consecutive failures (`CLIENT_FALL_THRESHOLD 20`).
   - Every established client connection immediately resets consecutive failures to zero (`record_backend_success()`), preventing false-positive trips.

---

## Interactive TUI Dashboard

When launched without `--no-tui`, ADLB displays an interactive real-time console:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ ADVANCED LOAD BALANCER v2.0  │ PORT: 8443 │ PROTO: TCP+TLS │ ALGO: LEAST-CONNECTIONS   │
├────┬────────────────────┬──────────┬──────────┬──────────┬────────┬──────────┬─────────┤
│ ID │ BACKEND ADDRESS    │ STATUS   │ WEIGHT   │ ACTIVE   │ TOTAL  │ LATENCY  │ FAIL/OK │
├────┼────────────────────┼──────────┼──────────┼──────────┼────────┼──────────┼─────────┤
│ 0  │ 127.0.0.1:9001     │ ● UP     │ 1        │ 12       │ 4502   │  0.31 ms │ 0/2     │
│ 1  │ 127.0.0.1:9002     │ ● UP     │ 1        │ 11       │ 4498   │  0.28 ms │ 0/2     │
└────┴────────────────────┴──────────┴──────────┴──────────┴────────┴──────────┴─────────┘
  Throughput: 8,450 req/s │ Active Clients: 23/4096 │ Uptime: 01h 14m 22s
```

### Interactive Keyboard Shortcuts
- **`[A]`**: Open popup dialog to switch routing algorithm on the fly without service restart.
- **`[H]`**: Toggle health checking mode (`TCP` ⇄ `HTTP` ⇄ `Payload`).
- **`[P]`**: Toggle upstream PROXY Protocol v1 injection.
- **`[R]`**: Reset handled request counters (`total_requests`).
- **`[Q]` / `[ESC]`**: Trigger graceful shutdown confirmation modal.

---

## Load Testing and Benchmarks (`test_client`)

The project includes `test_client`, a multithreaded benchmarking tool capable of generating high-throughput synthetic load:

```bash
# Example: 40 client threads, 5,000 total requests over TLS to port 8443
./test_client -t 127.0.0.1:8443 --ssl -c 40 -n 5000
```

### Sample Benchmark Report
At benchmark completion, the test client calculates latency percentiles and displays backend request distribution:

```
================================================================================
                       LOAD BALANCER TEST REPORT
================================================================================
Target Endpoint       : https://127.0.0.1:8443/
Mode / Protocol       : Layer 7 TCP / HTTP (TLS/SSL Termination)
Concurrency Level     : 40 client threads
Total Test Time       :  0.412 seconds
Completed Requests    : 5000
Successful Requests   : 5000 (100.00%)
Failed Requests       : 0 ( 0.00%)
Throughput (RPS)      : 12,135.92 req/sec
Data Transferred      :   0.65 MB (  1.58 MB/s)

Latency Distribution (Round-Trip Time):
  Min Latency         :   0.85 ms
  Avg Latency         :   3.21 ms
  Median (p50)        :   2.90 ms
  90% Percentile (p90):   5.10 ms
  95% Percentile (p95):   6.80 ms
  99% Percentile (p99):   9.45 ms
  Max Latency         :  14.20 ms

Backend Request Distribution Breakdown:
  Backend :9001       :   2500 reqs ( 50.0%) [██████████░░░░░░░░░░]
  Backend :9002       :   2500 reqs ( 50.0%) [██████████░░░░░░░░░░]
================================================================================
```

### Embedded Mock Backends
Spin up local mock servers for immediate stress-testing:
```bash
# Launch 3 non-blocking mock HTTP backends in C on ports 9001, 9002, 9003:
./test_client -M 3 --backend-port 9001 --backends-only

# Or launch high-concurrency multi-threaded Python 3 mock servers:
python3 tools/mock_server.py 9001
```

---

## Automated Test Suite (`make test`)

Run the complete test suite with zero external dependencies:

```bash
make test
```

### Test Coverage Highlights:
- **PROXY Protocol v1**: Serialization and stream decoding verification using UNIX `socketpair()` across fragmented payloads.
- **IPv4 RFC Validation**: Bounds and syntax checking for valid and malformed addresses.
- **Algorithm Verification**: Cycle correctness for Round-Robin, load balancing under variable active connections for Least-Connections, deterministic affinity for IP-Hash, and sampling under Random-2.
- **Circuit Breaker Transitions**: Threshold trips (`UP -> DOWN`), routing bypass around dead backends, and restoration on successful probe.
- **Underflow Protection**: Clamping guards preventing negative active connection counters on over-release.
- **MPSC Logger Stress**: High-contention concurrency validation (800 writes across 8 concurrent pthreads without race conditions or memory corruption).

---

## Security Hardening

The codebase incorporates defenses derived from formal security and code reviews:
- **SEC-01**: Descriptors exhaustion defense via automatic kernel soft-limit elevation (`increase_fd_limit()` on `RLIMIT_NOFILE`).
- **SEC-02**: Concurrent client threshold enforcement (`--max-connections`) with non-blocking drops to mitigate SYN-flood attacks.
- **SEC-03**: Strict CRLF injection sanitization within HTTP probe paths.
- **SEC-04**: RFC compliance verification and anti-fragmentation guards during PROXY Protocol v1 decoding.
- **SEC-05**: Modern hardened TLS profile (SSLv2, SSLv3, TLS 1.0, and TLS 1.1 disabled; AEAD ciphers prioritized; CRIME compression disabled).
- **SEC-06**: Spoofed datagram and NAT session starvation protection for UDP traffic.
- **SEC-07**: Strict input validation and DNS resolution for configured backend addresses.
- **SEC-08**: Reentrant, thread-safe UTF-8 terminal formatting (`mbrtowc`) in TUI routines.
- **SEC-09**: Mandatory private key file permission enforcement (`0600` or `0400`).

---

## Repository Structure

```
adlb/
├── Makefile                 # Master hierarchical Makefile
├── README.md                # Official project documentation (English)
├── LICENSE                  # Open-source MIT license
├── app/                     # Main executable application
│   ├── Makefile
│   └── main.c               # Entry-point, signal orchestration, worker dispatch
├── include/                 # Unified headers
│   ├── advlb/
│   └── advnet/
├── libs/
│   ├── libadvnet/           # Core Network Library
│   │   ├── include/advnet/  # net_core.h, net_epoll.h, net_proxy_proto.h
│   │   └── src/             # epoll/kqueue translation, sockets, PROXY protocol
│   └── libadvlb/            # Load Balancer Engine
│       ├── include/advlb/   # balancer.h, config.h, health_check.h, log.h, proxy.h, tui.h
│       └── src/             # Worker pool, lock-free routing, MPSC logging, TUI
├── tools/                   # Benchmarking and mock backends
│   ├── Makefile
│   ├── test_client.c        # Multithreaded benchmarking client (C11)
│   └── mock_server.py       # Multithreaded HTTP mock server (Python 3)
├── tests/                   # Automated test suite (make test)
│   ├── Makefile
│   └── test_suite.c         # 33 unit and integration test assertions
└── certs/                   # Sample test certificates
    ├── server.crt
    └── server.key
```

---

## License

This project is open-source software licensed under the [MIT License](LICENSE).
