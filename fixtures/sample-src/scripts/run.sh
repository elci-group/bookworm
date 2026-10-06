#!/bin/bash
set -euo pipefail
cargo run -p sample-src -- "$@"
