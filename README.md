# Proxy Probe

`proxy_probe.py` is a production-oriented proxy configuration tester for **VLESS**, **VMess**, **Trojan**, and **Shadowsocks** links.

It starts a temporary local Xray or Shadowsocks client, exposes a local SOCKS port, sends HTTP validation requests through that SOCKS proxy, then saves the configs that actually connect.

The default behavior is intentionally small and server-friendly:

```text
connected.txt
summary.json
proxy_probe.log
```

No per-proxy log folder, CSV, JSONL, or bucket files are created unless you explicitly ask for them.

---

## Features

- Supports `vless://`, `vmess://`, `trojan://`, and `ss://` configs.
- Uses Xray for VLESS, VMess, and Trojan.
- Uses `ss-local` for Shadowsocks.
- Tests through a real local SOCKS proxy.
- Has four testing modes: `fast`, `balanced`, `strict`, and `diagnose`.
- Designed for unstable networks where slow or partial connectivity should not always mean dead.
- Saves selected configs immediately while the run is still active.
- Writes a small `summary.json` for automation or web server usage.
- Can run quietly with no console progress.
- Can optionally save failed, unknown, bucketed, CSV, JSONL, and per-proxy log outputs.

---

## Requirements

### Python packages

```bash
pip install aiohttp aiohttp-socks
```

This installs the async HTTP client and SOCKS connector used by the tester.

### Runtime clients

You also need these binaries available in your `PATH`:

```bash
xray
ss-local
```

`xray` is used for VLESS, VMess, and Trojan configs.  
`ss-local` is used for Shadowsocks configs.

You can use custom binary paths with:

```bash
--xray-bin /path/to/xray
--ss-bin /path/to/ss-local
```

---

## Input file format

Create a text file with one proxy config per line:

```text
vless://...
vmess://...
trojan://...
ss://...
```

Empty lines are ignored. Lines starting with `#` are ignored.

Example:

```text
# my configs
vless://uuid@example.com:443?security=tls&type=ws&path=/ws#example
vmess://eyJhZGQiOiAiZXhhbXBsZS5jb20iLCAicG9ydCI6ICI0NDMiLCAiaWQiOiAiLi4uIn0=
ss://...
```

---

## Quick start

```bash
python proxy_probe.py -f configs.txt --mode fast
```

This is the simplest useful command.

It reads `configs.txt`, quickly removes obviously useless configs, and writes selected configs to:

```text
connected.txt
```

It also creates:

```text
summary.json
proxy_probe.log
```

Use this when you have a large list and want a first cleanup pass.

---

## Modes

### `fast`

Fast bulk screening mode.

```bash
python proxy_probe.py -f configs.txt --mode fast --threads 100
```

Use this for very large lists, for example 10,000 to 70,000 configs.

What it does:

- Parses the config.
- Builds a temporary Xray or Shadowsocks config.
- Starts the local client.
- Waits for the local SOCKS port.
- Tries HTTP validation endpoints.
- Stops after the first successful endpoint.

This mode is intentionally forgiving. It is good for removing obvious junk without over-testing every config.

Default behavior:

```text
threads: 100
startup timeout: 8s
test timeout: 10s
per-proxy timeout: 25s
local DNS diagnostics: off
Stage2 strict checks: off
```

Created files by default:

```text
connected.txt
summary.json
proxy_probe.log
```

---

### `balanced`

Safer everyday mode.

```bash
python proxy_probe.py -f configs.txt --mode balanced --threads 60
```

Use this when you want better diagnostics than `fast`, but you do not want the heavy strict checks.

What it adds compared to `fast`:

- Local DNS diagnostics before client startup.
- Better stage-level failure information.
- Still avoids heavy Stage2 checks.
- Still stops after enough evidence of connectivity.

Default behavior:

```text
threads: 60
startup timeout: 10s
test timeout: 15s
per-proxy timeout: 40s
local DNS diagnostics: on
Stage2 strict checks: off
```

Created files by default:

```text
connected.txt
summary.json
proxy_probe.log
```

Recommended when you want a safer default for unstable networks.

---

### `strict`

Quality-selection mode.

```bash
python proxy_probe.py -f connected.txt --mode strict --threads 30 --output selected.txt
```

Use this after a first fast or balanced pass.

Strict mode runs stronger Stage2-style checks:

- DNS-over-proxy test.
- HTTPS test.
- Multi-domain test.
- Stability test.

It is useful for selecting stronger configs from a smaller candidate list.

Default behavior:

```text
threads: 30
startup timeout: 12s
test timeout: 15s
per-proxy timeout: 70s
local DNS diagnostics: on
Stage2 strict checks: on
```

Created files by default:

```text
selected.txt      # if you used --output selected.txt
summary.json
proxy_probe.log
```

Important note:

Strict mode is stronger, but it should not be used as the first pass for huge unstable lists. Some slow but real configs may fail strict checks because the internet path is unstable, not because the config is truly dead.

---

### `diagnose`

Debugging mode.

```bash
python proxy_probe.py -f broken.txt --mode diagnose --debug --jsonl results.jsonl
```

Use this when configs work on one machine but fail on another machine, or when you need to know exactly where the failure happens.

What it does:

- Runs local DNS diagnostics.
- Tests all validation endpoints.
- Captures richer failure information.
- Enables Xray debug loglevel when `--debug` is used.
- Can write detailed JSONL and per-proxy logs if requested.

Default behavior:

```text
threads: 10
startup timeout: 15s
test timeout: 20s
per-proxy timeout: 90s
local DNS diagnostics: on
Stage2 strict checks: off
test all HTTP endpoints: on
```

Created files by default:

```text
connected.txt
summary.json
proxy_probe.log
```

For deeper logs, add:

```bash
--per-proxy-logs --jsonl results.jsonl
```

---

## Recommended workflows

### 1. Huge list cleanup

```bash
python proxy_probe.py \
  -f configs_70000.txt \
  --mode fast \
  --threads 100 \
  --output candidates.txt \
  --save-unknown unknown.txt \
  --quiet
```

This is the best first pass for very large lists.

It saves configs that connected to:

```text
candidates.txt
```

It also saves inconclusive configs to:

```text
unknown.txt
```

This is useful under unstable internet because a timeout does not always mean the config is dead.

Created files:

```text
candidates.txt
unknown.txt
summary.json
proxy_probe.log
```

---

### 2. Safer general test

```bash
python proxy_probe.py \
  -f configs.txt \
  --mode balanced \
  --threads 60 \
  --output connected.txt \
  --save-unknown unknown.txt
```

Use this when you want more reliable testing than `fast`, but you still want to avoid strict over-filtering.

Created files:

```text
connected.txt
unknown.txt
summary.json
proxy_probe.log
```

---

### 3. Select the best configs from candidates

```bash
python proxy_probe.py \
  -f candidates.txt \
  --mode strict \
  --threads 30 \
  --output selected.txt
```

Use this after fast screening.

It runs stronger validation and writes the selected configs to:

```text
selected.txt
```

Created files:

```text
selected.txt
summary.json
proxy_probe.log
```

---

### 4. Strict mode with soft buckets

```bash
python proxy_probe.py \
  -f candidates.txt \
  --mode strict \
  --threads 30 \
  --output selected.txt \
  --save-buckets
```

Use this when you want to see what happened to every config category.

Created files:

```text
selected.txt
good.txt
slow.txt
partial.txt
unstable.txt
dead.txt
unknown.txt
parse_failed.txt
summary.json
proxy_probe.log
```

Bucket meaning:

| File | Meaning |
|---|---|
| `good.txt` | Strong successful configs |
| `slow.txt` | Connected but slow |
| `partial.txt` | Some checks passed, some failed |
| `unstable.txt` | Intermittent success |
| `dead.txt` | Strong evidence of failure |
| `unknown.txt` | Inconclusive failure, usually timeout/network instability |
| `parse_failed.txt` | Invalid or unsupported config format |

---

### 5. Web server usage

```bash
python proxy_probe.py \
  -f /data/jobs/job_123/input.txt \
  --mode fast \
  --threads 100 \
  --output /data/jobs/job_123/connected.txt \
  --summary /data/jobs/job_123/summary.json \
  --log-file /data/jobs/job_123/proxy_probe.log \
  --quiet
```

Use this when another process or web server starts the test.

`--quiet` disables console progress output, but the script still writes:

```text
connected.txt
summary.json
proxy_probe.log
```

Your web server can read `summary.json` when the process exits.

---

### 6. Minimal run without log file

```bash
python proxy_probe.py \
  -f configs.txt \
  --mode fast \
  --quiet \
  --no-log-file
```

Use this only if your supervisor, Docker container, or web server already captures logs.

Created files:

```text
connected.txt
summary.json
```

---

### 7. Diagnose why configs fail

```bash
python proxy_probe.py \
  -f suspicious.txt \
  --mode diagnose \
  --threads 10 \
  --debug \
  --jsonl results.jsonl \
  --per-proxy-logs
```

Use this for debugging a smaller list.

Created files:

```text
connected.txt
results.jsonl
summary.json
proxy_probe.log
proxy_logs/
```

`proxy_logs/` contains Xray or `ss-local` output for each config.

This is useful for identifying:

- TLS handshake errors.
- Reality public key or short ID problems.
- Client startup problems.
- Local SOCKS binding problems.
- DNS problems.
- Remote connection resets.
- Dial timeouts.

---

### 8. Full report run

```bash
python proxy_probe.py \
  -f configs.txt \
  --mode diagnose \
  --threads 20 \
  --jsonl results.jsonl \
  --csv results.csv \
  --save-failed failed.txt \
  --save-unknown unknown.txt \
  --save-buckets \
  --per-proxy-logs
```

Use this only when you want maximum observability.

Created files:

```text
connected.txt
failed.txt
unknown.txt
good.txt
slow.txt
partial.txt
unstable.txt
dead.txt
parse_failed.txt
results.jsonl
results.csv
summary.json
proxy_probe.log
proxy_logs/
```

This is intentionally not the default because it can create a lot of output.

---

## Output files

### Default files

| File | Created by default? | Purpose |
|---|---:|---|
| `connected.txt` | Yes | Selected configs from the run |
| `summary.json` | Yes | Small machine-readable run summary |
| `proxy_probe.log` | Yes | Full run log |

### Optional files

| Flag | File(s) | Purpose |
|---|---|---|
| `--save-failed failed.txt` | `failed.txt` | Save definitely failed configs |
| `--save-unknown unknown.txt` | `unknown.txt` | Save inconclusive configs separately |
| `--save-buckets` | `good.txt`, `slow.txt`, `partial.txt`, `unstable.txt`, `dead.txt`, `unknown.txt`, `parse_failed.txt` | Save configs by classification |
| `--jsonl results.jsonl` | `results.jsonl` | Detailed machine-readable per-config results |
| `--csv results.csv` | `results.csv` | Spreadsheet-friendly report |
| `--per-proxy-logs` | `proxy_logs/` | Xray/ss-local logs per config |

---

## Classification system

The script does not only think in `success` and `failed`.

It classifies results as:

| Classification | Meaning |
|---|---|
| `GOOD` | Strong successful config |
| `SLOW_BUT_WORKING` | Connected, but slower than the slow threshold |
| `PARTIAL` | Some validations worked, some failed |
| `UNSTABLE` | Intermittent success |
| `UNKNOWN` | Inconclusive failure, often timeout or unstable network |
| `DEAD` | Strong evidence that the config is not usable |
| `PARSE_FAILED` | Invalid or unsupported config format |

By default, `connected.txt` includes selected connected configs. In `fast` and `balanced`, this is intentionally more forgiving. In `strict`, selection is stronger.

For unstable internet, keep `UNKNOWN` configs separately with:

```bash
--save-unknown unknown.txt
```

That prevents slow or temporarily blocked configs from being permanently deleted.

---

## Stages

Each config can fail at a specific stage:

```text
PARSE
DNS_RESOLUTION
BUILD_CONFIG
CLIENT_START
WAIT_FOR_LOCAL_SOCKS
HTTP_TEST
RESPONSE_VALIDATION
STAGE2_DNS_OVER_PROXY
STAGE2_HTTPS
STAGE2_MULTI_DOMAIN
STAGE2_STABILITY
CLIENT_SHUTDOWN
```

Examples:

```text
FAIL stage=WAIT_FOR_LOCAL_SOCKS category=TIMEOUT_ERROR
FAIL stage=HTTP_TEST category=HTTP_ERROR
FAIL stage=DNS_RESOLUTION category=DNS_ERROR
```

This is useful when the same configs work on one machine but fail on another.

---

## Timeout tuning

Default timeouts depend on mode:

| Mode | Threads | Startup timeout | Test timeout | Per-proxy timeout |
|---|---:|---:|---:|---:|
| `fast` | 100 | 8s | 10s | 25s |
| `balanced` | 60 | 10s | 15s | 40s |
| `strict` | 30 | 12s | 15s | 70s |
| `diagnose` | 10 | 15s | 20s | 90s |

You can override them:

```bash
python proxy_probe.py \
  -f configs.txt \
  --mode fast \
  --startup-timeout 12 \
  --test-timeout 20 \
  --per-proxy-timeout 45
```

Use this when many configs are slow but still possibly usable.

---

## Slow threshold

Configs slower than this threshold are classified as `SLOW_BUT_WORKING`:

```bash
--slow-threshold-ms 8000
```

Default:

```text
8000 ms
```

Example for very weak internet:

```bash
python proxy_probe.py \
  -f configs.txt \
  --mode balanced \
  --slow-threshold-ms 12000 \
  --save-unknown unknown.txt
```

This makes the tester more forgiving.

---

## Console output

By default, the script prints clean progress lines with loud colors if the terminal supports color.

Example:

```text
[PROGRESS] 5000/70000 | selected=91 failed=4909 unknown=84 active=100 | rate=1.82% | avg=6.1s | elapsed=88s
config 5042/70000: status=GOOD stage=HTTP_TEST latency=4200ms
config 5043/70000: status=DEAD stage=WAIT_FOR_LOCAL_SOCKS reason=timeout
config 5044/70000: status=UNKNOWN stage=HTTP_TEST reason=all endpoints timed out
```

Disable console color:

```bash
--no-color
```

Disable console progress entirely:

```bash
--quiet
```

Control progress frequency:

```bash
--progress-interval 10
--progress-every 500
```

Explanation:

- `--progress-interval 10` prints a loud summary roughly every 10 seconds.
- `--progress-every 500` also prints a loud summary every 500 completed configs.

---

## Custom validation endpoints

The script has built-in HTTP validation endpoints.

For diagnostics, you can override or add custom endpoints:

```bash
python proxy_probe.py \
  -f configs.txt \
  --mode diagnose \
  --test-url https://api.ipify.org?format=json \
  --test-url https://icanhazip.com
```

Use this when a specific endpoint is blocked or unreliable on your network.

For normal usage, you usually do not need this flag.

---

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Completed and selected at least one config |
| `1` | Completed but selected no configs, or no input configs were provided |
| `2` | CLI, dependency, or input file error |
| `130` | Interrupted by user |

---

## Practical recommendations

### For huge lists

Use:

```bash
--mode fast --threads 100 --save-unknown unknown.txt
```

Do not start with strict mode.

### For unstable internet

Use:

```bash
--mode balanced --save-unknown unknown.txt --slow-threshold-ms 12000
```

This avoids deleting slow-but-real configs.

### For final selection

Use:

```bash
--mode strict --threads 30
```

Run this only on configs that survived a fast or balanced pass.

### For debugging

Use:

```bash
--mode diagnose --debug --jsonl results.jsonl --per-proxy-logs
```

Run this on a smaller subset, not on 70,000 configs.

---

## Common mistakes

### Using strict mode as the first pass

Avoid this for large unstable lists.

Strict mode is useful, but it can reject configs that are technically connected but too slow or inconsistent at the moment of testing.

### Treating timeout as definitely dead

A timeout may mean:

- the config is dead,
- the network is unstable,
- the endpoint is blocked,
- DNS is bad,
- the server is temporarily slow.

Use:

```bash
--save-unknown unknown.txt
```

### Creating too many logs by accident

Do not use this on huge lists unless you really need it:

```bash
--per-proxy-logs
```

It can create a large `proxy_logs/` directory.

---
# UPDATE

## Sort configurations by ping

`proxy_probe.py` supports `--sort-ping` for ordering configurations by latency.

### Full proxy test + sorted output

Use this when you want to run a normal proxy test first, then save the working/selected configurations sorted from fastest to slowest.

```bash
python3 proxy_probe.py --mode balanced -f configs.txt --sort-ping --output sorted.txt
```

Behavior:

* Runs the selected test mode normally.
* Writes only selected/working configurations to the output file.
* Sorts the output by the best measured latency available.

### Ping-only sorting without `--mode`

If `--sort-ping` is used without `--mode`, the script does not run a full proxy test. Instead, it quickly checks TCP reachability to each configuration server/port and sorts the whole list by ping.

```bash
python3 proxy_probe.py -f configs.txt --sort-ping --ping-timeout 5 --output sorted.txt
```

Example output:

```text
output file sorted sorted.txt
from 600th configuration, configs connections dies because of timeout :(
```

Notes:

* Ping-only mode is a fast reachability check, not a full proxy tunnel validation.
* A config can respond to TCP ping but still fail the full proxy test.
* For reliable filtering, use `--mode balanced --sort-ping`.
* For quick large-list ordering, use `--sort-ping` without `--mode`.

---
## Help

Show all options:

```bash
python proxy_probe.py -h
```

