#!/usr/bin/env python3
"""Compare direct Bookworm HTTP service latency with the Tov proxy.

The script uses only the Python standard library. It starts both services,
creates a small in-scope source file and cache, checks cached-read response
equivalence, then measures health and cached reads at low and high concurrency.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import math
import os
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import shutil
from pathlib import Path
from typing import Any


IGNORED_KEYS = {"timestamp_unix", "cache_hit", "pisa_status"}


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request(base: str, path: str, method: str = "GET", body: bytes | None = None,
            timeout: float = 10.0) -> tuple[int, bytes]:
    headers = {"Connection": "close"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def wait_ready(base: str, process: subprocess.Popen[bytes], label: str,
               timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    last_error = "no response"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"{label} exited early with status {process.returncode}")
        try:
            status, payload = request(base, "/v1/health", timeout=1.0)
            if status == 200:
                return
            last_error = f"HTTP {status}: {payload[:200]!r}"
        except (OSError, TimeoutError) as exc:
            last_error = str(exc)
        time.sleep(0.1)
    raise RuntimeError(f"{label} did not become ready: {last_error}")


def normalized(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: normalized(item) for key, item in value.items()
                if key.lower() not in IGNORED_KEYS and not key.lower().endswith("_timestamp")}
    if isinstance(value, list):
        return [normalized(item) for item in value]
    return value


def percentile(samples: list[float], pct: float) -> float:
    ordered = sorted(samples)
    if len(ordered) == 1:
        return ordered[0]
    index = (len(ordered) - 1) * pct / 100
    lo, hi = math.floor(index), math.ceil(index)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (index - lo)


def run_benchmark(base: str, route: str, payload: bytes | None, workers: int,
                  requests: int, timeout: float) -> dict[str, float | int]:
    method = "POST" if payload is not None else "GET"
    barrier = threading.Barrier(min(workers, requests))
    local = threading.local()

    def one(_: int) -> float:
        # Synchronize the first request of each worker so concurrency is real.
        if not getattr(local, "started", False):
            try:
                barrier.wait(timeout=10)
            except threading.BrokenBarrierError:
                pass
            local.started = True
        started = time.perf_counter()
        status, body = request(base, route, method, payload, timeout)
        elapsed = time.perf_counter() - started
        if status != 200:
            raise RuntimeError(f"{method} {route} returned HTTP {status}: {body[:500]!r}")
        return elapsed

    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        samples = list(pool.map(one, range(requests)))
    duration = time.perf_counter() - started
    return {
        "requests": requests,
        "concurrency": workers,
        "duration_seconds": round(duration, 6),
        "requests_per_second": round(requests / duration, 2),
        "p50_ms": round(statistics.median(samples) * 1000, 3),
        "p95_ms": round(percentile(samples, 95) * 1000, 3),
    }


def terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bookworm", type=Path, default=Path("target/release/bookworm"),
                        help="release Bookworm executable")
    parser.add_argument("--proxy", type=Path, default=Path("experiments/tov-http/proxy"),
                        help="Tov proxy executable")
    parser.add_argument("--requests", type=int, default=100,
                        help="requests per route and concurrency level")
    parser.add_argument("--high-concurrency", type=int, default=16)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()
    if args.requests < 1 or args.high_concurrency < 2:
        parser.error("--requests must be positive and --high-concurrency at least 2")
    bookworm = args.bookworm.resolve()
    proxy = args.proxy.resolve()
    if not bookworm.is_file() or not os.access(bookworm, os.X_OK):
        parser.error(f"Bookworm executable not found or not executable: {bookworm}")
    if not proxy.is_file() or not os.access(proxy, os.X_OK):
        parser.error(f"proxy executable not found or not executable: {proxy}")

    direct_proc: subprocess.Popen[bytes] | None = None
    proxy_proc: subprocess.Popen[bytes] | None = None
    with tempfile.TemporaryDirectory(prefix="bookworm-tov-bench-") as temp_name:
        root = Path(temp_name)
        fixture = root / "bench.rs"
        source = Path(__file__).resolve().parents[2] / "crates/bookworm-cli/src/lib.rs"
        shutil.copyfile(source, fixture)
        cache = root / "cache"
        cache.mkdir()
        direct_port, proxy_port = free_port(), free_port()
        direct_url = f"http://127.0.0.1:{direct_port}"
        proxy_url = f"http://127.0.0.1:{proxy_port}"
        direct_proc = subprocess.Popen(
            [str(bookworm), "--root", str(root), "--cache-dir", str(cache), "serve",
             "--bind", f"127.0.0.1:{direct_port}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        proxy_env = os.environ.copy()
        proxy_env.update({"BOOKWORM_BACKEND_PORT": str(direct_port),
                          "TOV_LISTEN_PORT": str(proxy_port)})
        proxy_proc = subprocess.Popen([str(proxy)], cwd=proxy.parent, env=proxy_env,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            wait_ready(direct_url, direct_proc, "Bookworm", args.timeout)
            wait_ready(proxy_url, proxy_proc, "Tov proxy", args.timeout)

            read_body = json.dumps({"target": str(fixture), "fidelity": "lossless"},
                                   separators=(",", ":")).encode()
            direct_status, direct_raw = request(direct_url, "/v1/read", "POST", read_body,
                                                args.timeout)
            proxy_status, proxy_raw = request(proxy_url, "/v1/read", "POST", read_body,
                                              args.timeout)
            if direct_status != 200 or proxy_status != 200:
                raise RuntimeError(f"warmup failed: direct={direct_status} {direct_raw[:300]!r}; "
                                   f"proxy={proxy_status} {proxy_raw[:300]!r}")
            direct_json, proxy_json = json.loads(direct_raw), json.loads(proxy_raw)
            equivalent = normalized(direct_json) == normalized(proxy_json)
            if not equivalent:
                raise RuntimeError("/v1/read responses differ after timestamp/cache-marker normalization")

            cases = {
                "health": ("/v1/health", None),
                "read_cached": ("/v1/read", read_body),
            }
            report: dict[str, Any] = {
                "services": {"bookworm": str(bookworm), "proxy": str(proxy),
                             "bookworm_url": direct_url, "proxy_url": proxy_url},
                "read_response_equivalence": {
                    "equivalent": True,
                    "normalization_ignored_keys": sorted(IGNORED_KEYS),
                },
                "benchmarks": {},
            }
            for name, (route, payload) in cases.items():
                for concurrency in (1, args.high_concurrency):
                    key = f"{name}_concurrency_{concurrency}"
                    report["benchmarks"][key] = {
                        "direct": run_benchmark(direct_url, route, payload, concurrency,
                                                 args.requests, args.timeout),
                        "proxy": run_benchmark(proxy_url, route, payload, concurrency,
                                                args.requests, args.timeout),
                    }
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0
        finally:
            terminate(proxy_proc)
            terminate(direct_proc)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, json.JSONDecodeError) as error:
        print(f"benchmark failed: {error}", file=sys.stderr)
        raise SystemExit(1)
