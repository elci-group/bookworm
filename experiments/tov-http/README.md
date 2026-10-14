# Tov HTTP proxy benchmark

This experiment compares the direct Bookworm HTTP service with a Tov 0.0.1
process that handles its own health route and forwards API requests to a
separate Bookworm process. The proxy is a separate process, and `/v1/read`
responses are returned as the Bookworm JSON envelope.

## Build

From the repository root, build the original revision in a separate worktree,
then build the current source with the Rust accept-loop polling fix:

```sh
git worktree add /tmp/bookworm-tov-baseline 6f50b00
cargo build --release --offline --manifest-path /tmp/bookworm-tov-baseline/Cargo.toml -p bookworm-cli
cargo build --release --offline -p bookworm-cli
```

Build the Tov proxy from this directory. On the host used for the reported
measurements, the linker needed the GCC 13 library directory and Tov's cache
was kept under `/tmp`:

```sh
cd experiments/tov-http
LIBRARY_PATH=/usr/lib/gcc/x86_64-linux-gnu/13 \
TOV_CACHE_DIR=/tmp/bookworm-tov-cache \
tov build proxy.tov -o proxy
cd ../..
```

The proxy reads `TOV_LISTEN_PORT` and `BOOKWORM_BACKEND_PORT`; the benchmark
assigns free loopback ports for both processes. It launches Bookworm with an
isolated temporary fixture and cache, warms the read route, compares the JSON
envelopes after ignoring volatile `timestamp_unix`, `cache_hit`, and
`pisa_status` fields, then measures direct and proxied health and cached-read
requests.

## Run

Run the same 500-request workload against the original executable and the
modified release executable:

```sh
python3 experiments/tov-http/bench.py \
  --bookworm /tmp/bookworm-tov-baseline/target/release/bookworm \
  --proxy experiments/tov-http/proxy \
  --requests 500 --high-concurrency 16

python3 experiments/tov-http/bench.py \
  --bookworm target/release/bookworm \
  --proxy experiments/tov-http/proxy \
  --requests 500 --high-concurrency 16
```

Each invocation prints JSON with requests per second, p50/p95 request latency,
and response-equivalence status. Requests use Python `urllib` with
`Connection: close`. The benchmark runs scenarios sequentially: direct then
proxy, at concurrency 1 and 16. The values below came from one host and are
not a cross-machine performance claim.

## Results and conclusion

Direct Bookworm measurements from the original release artifact and the build
with the Rust poll accept-loop fix:

| Route | Concurrency | Original release | Modified release |
|---|---:|---:|---:|
| Health | 1 | 49.32 req/s, p95 20.585 ms | 3,762.96 req/s, p95 0.375 ms |
| Cached read | 1 | 39.58 req/s, p95 29.074 ms | 148.68 req/s, p95 8.925 ms |
| Cached read | 16 | 189.01 req/s, p95 102.973 ms | 191.28 req/s, p95 108.631 ms |

Tov 0.0.1 serves its own health response quickly, but forwarding a cached
Bookworm read does not improve the backend's read performance. The Rust poll
accept-loop fix makes a substantial difference for single-client health and
cached reads. At concurrency 16, cached-read throughput is essentially flat
and p95 is slightly higher in this run, so these measurements do not show a
high-concurrency read improvement.

The proxy and direct read envelopes matched after the volatile fields listed
above were ignored. Because every scenario used a single host, Python
`urllib`, closed connections, and sequential execution, treat the figures as
an experiment result rather than a general performance guarantee.
