#!/usr/bin/env python3
"""
proxy_probe.py

Merged proxy tester for VLESS, VMess, Trojan, and Shadowsocks.

Design goals:
- Minimal output by default: connected.txt, summary.json, proxy_probe.log
- Modes: fast, balanced, strict, diagnose
- Safe classification for unstable networks: GOOD / SLOW_BUT_WORKING / PARTIAL /
  UNSTABLE / UNKNOWN / DEAD / PARSE_FAILED
- No per-proxy logs unless requested
- Stage-based diagnostics and immediate output writes
"""

from __future__ import annotations

VERSION = "2026-06-09-sort-ping"

import argparse
import asyncio
import base64
import csv
import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import sys
import tempfile
import time
from collections import Counter, defaultdict, deque
from contextlib import suppress
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib.parse import parse_qsl, unquote, urlparse

try:
    import aiohttp
    from aiohttp_socks import ProxyConnector

    IMPORT_ERROR: Optional[BaseException] = None
except ImportError as exc:  # keep --help usable even when runtime deps are missing
    aiohttp = None  # type: ignore[assignment]
    ProxyConnector = None  # type: ignore[assignment]
    IMPORT_ERROR = exc


LOCAL_HOST = "127.0.0.1"
READINESS_CHECK_INTERVAL = 0.25
DEFAULT_PROGRESS_INTERVAL = 5.0
DEFAULT_PROGRESS_EVERY = 100

BASIC_TEST_URLS = [
    # Keep the old tester's lenient endpoint strategy first.  Plain HTTP is
    # intentional: on weak/unstable networks HTTPS validation can fail even
    # when the proxy tunnel itself is usable.
    "https://api.ipify.org?format=json",
    "https://httpbin.org/ip",
    "http://httpbin.org/ip",
    "https://icanhazip.com",
    "http://icanhazip.com",
    "https://ifconfig.me/ip",
    "https://www.cloudflare.com/cdn-cgi/trace",
]

STAGE2_DNS_TEST_URL = "https://dns.google/resolve?name=google.com&type=A"
STAGE2_DNS_EXPECTED_KEYS = {"Status", "Answer"}
STAGE2_HTTPS_TEST_URL = "https://www.cloudflare.com/cdn-cgi/trace"
STAGE2_MULTI_DOMAIN_URLS = [
    "https://www.google.com/generate_204",
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://www.wikipedia.org/",
]
STAGE2_STABILITY_URLS = [
    "https://www.google.com/generate_204",
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://www.wikipedia.org/",
]
STAGE2_STABILITY_ROUNDS = 3
STAGE2_MIN_STABILITY_SUCCESSES = 2
DEFAULT_SLOW_THRESHOLD_MS = 8000.0

CSV_COLUMNS = [
    "index",
    "proxy_id",
    "proxy",
    "type",
    "mode",
    "classification",
    "selected",
    "connected",
    "stage",
    "failure_category",
    "failure_reason",
    "dns_time_ms",
    "startup_time_ms",
    "socks_ready_time_ms",
    "http_time_ms",
    "stage2_time_ms",
    "total_time_ms",
    "resolved_ips",
    "endpoint_used",
    "endpoint_success_count",
    "stage2_stability_success_count",
    "stage2_avg_latency_ms",
    "log_file",
]


class Mode(str, Enum):
    FAST = "fast"
    BALANCED = "balanced"
    STRICT = "strict"
    DIAGNOSE = "diagnose"


class Stage(str, Enum):
    PARSE = "PARSE"
    DNS_RESOLUTION = "DNS_RESOLUTION"
    BUILD_CONFIG = "BUILD_CONFIG"
    CLIENT_START = "CLIENT_START"
    WAIT_FOR_LOCAL_SOCKS = "WAIT_FOR_LOCAL_SOCKS"
    HTTP_TEST = "HTTP_TEST"
    RESPONSE_VALIDATION = "RESPONSE_VALIDATION"
    STAGE2_DNS_OVER_PROXY = "STAGE2_DNS_OVER_PROXY"
    STAGE2_HTTPS = "STAGE2_HTTPS"
    STAGE2_MULTI_DOMAIN = "STAGE2_MULTI_DOMAIN"
    STAGE2_STABILITY = "STAGE2_STABILITY"
    CLIENT_SHUTDOWN = "CLIENT_SHUTDOWN"


class FailureCategory(str, Enum):
    PARSE_ERROR = "PARSE_ERROR"
    DNS_ERROR = "DNS_ERROR"
    BUILD_ERROR = "BUILD_ERROR"
    CLIENT_START_ERROR = "CLIENT_START_ERROR"
    SOCKS_ERROR = "SOCKS_ERROR"
    TLS_ERROR = "TLS_ERROR"
    REALITY_ERROR = "REALITY_ERROR"
    HTTP_ERROR = "HTTP_ERROR"
    TIMEOUT_ERROR = "TIMEOUT_ERROR"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"


class Classification(str, Enum):
    GOOD = "GOOD"
    SLOW_BUT_WORKING = "SLOW_BUT_WORKING"
    PARTIAL = "PARTIAL"
    UNSTABLE = "UNSTABLE"
    UNKNOWN = "UNKNOWN"
    DEAD = "DEAD"
    PARSE_FAILED = "PARSE_FAILED"


CONNECTED_CLASSES = {
    Classification.GOOD,
    Classification.SLOW_BUT_WORKING,
    Classification.PARTIAL,
    Classification.UNSTABLE,
}


@dataclass(frozen=True)
class ModeDefaults:
    threads: int
    startup_timeout: float
    test_timeout: float
    per_proxy_timeout: float
    test_all_endpoints: bool
    run_local_dns: bool
    run_stage2: bool


MODE_DEFAULTS: dict[Mode, ModeDefaults] = {
    Mode.FAST: ModeDefaults(
        threads=100,
        startup_timeout=8.0,
        test_timeout=10.0,
        per_proxy_timeout=25.0,
        test_all_endpoints=False,
        run_local_dns=False,
        run_stage2=False,
    ),
    Mode.BALANCED: ModeDefaults(
        threads=60,
        startup_timeout=10.0,
        test_timeout=15.0,
        per_proxy_timeout=40.0,
        test_all_endpoints=False,
        run_local_dns=True,
        run_stage2=False,
    ),
    Mode.STRICT: ModeDefaults(
        threads=30,
        startup_timeout=12.0,
        test_timeout=15.0,
        per_proxy_timeout=70.0,
        test_all_endpoints=False,
        run_local_dns=True,
        run_stage2=True,
    ),
    Mode.DIAGNOSE: ModeDefaults(
        threads=10,
        startup_timeout=15.0,
        test_timeout=20.0,
        per_proxy_timeout=90.0,
        test_all_endpoints=True,
        run_local_dns=True,
        run_stage2=False,
    ),
}


@dataclass(frozen=True)
class AppConfig:
    input_file: Optional[Path]
    mode: Mode
    threads: int
    startup_timeout: float
    test_timeout: float
    per_proxy_timeout: float
    output: Path
    summary_path: Path
    log_file: Optional[Path]
    quiet: bool
    no_color: bool
    debug: bool
    progress_interval: float
    progress_every: int
    xray_bin: str
    ss_bin: str
    fsync_output: bool
    save_failed: Optional[Path]
    save_unknown: Optional[Path]
    save_buckets: bool
    jsonl_path: Optional[Path]
    csv_path: Optional[Path]
    per_proxy_logs: bool
    proxy_log_dir: Path
    test_urls: list[str]
    slow_threshold_ms: float
    append: bool
    sort_ping: bool
    sort_ping_only: bool
    ping_timeout: float


@dataclass
class Latencies:
    dns_time_ms: Optional[float] = None
    startup_time_ms: Optional[float] = None
    socks_ready_time_ms: Optional[float] = None
    http_time_ms: Optional[float] = None
    stage2_time_ms: Optional[float] = None
    total_time_ms: Optional[float] = None


@dataclass
class DNSInfo:
    host: str = ""
    resolved_ips: list[str] = field(default_factory=list)
    families: list[str] = field(default_factory=list)
    dns_time_ms: Optional[float] = None
    error: str = ""


@dataclass
class EndpointResult:
    endpoint: str
    success: bool
    latency_ms: float
    status: Optional[int] = None
    observed_ip: str = ""
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HTTPStageResult:
    success: bool
    endpoint_used: str = ""
    observed_ip: str = ""
    endpoint_results: list[EndpointResult] = field(default_factory=list)
    stage: Stage = Stage.HTTP_TEST
    category: FailureCategory = FailureCategory.UNKNOWN_ERROR
    reason: str = ""
    elapsed_ms: float = 0.0

    @property
    def success_count(self) -> int:
        return sum(1 for item in self.endpoint_results if item.success)

    @property
    def failure_count(self) -> int:
        return sum(1 for item in self.endpoint_results if not item.success)


@dataclass
class Stage2CheckResult:
    dns_ok: bool = False
    https_ok: bool = False
    multi_domain_ok: bool = False
    stability_ok: bool = False
    dns_reason: str = ""
    https_reason: str = ""
    multi_domain_reason: str = ""
    stability_reason: str = ""
    multi_domain_success_count: int = 0
    multi_domain_total: int = 0
    stability_success_count: int = 0
    stability_rounds: int = STAGE2_STABILITY_ROUNDS
    avg_latency_ms: Optional[float] = None
    elapsed_ms: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TestResult:
    index: int
    total: int
    proxy: str
    proxy_id: str
    mode: Mode
    proxy_type: str = ""
    classification: Classification = Classification.UNKNOWN
    selected: bool = False
    connected: bool = False
    stage: Stage = Stage.PARSE
    failure_category: str = ""
    failure_reason: str = ""
    local_port: Optional[int] = None
    dns: DNSInfo = field(default_factory=DNSInfo)
    endpoint_used: str = ""
    http: Optional[HTTPStageResult] = None
    stage2: Optional[Stage2CheckResult] = None
    log_file: str = ""
    latencies: Latencies = field(default_factory=Latencies)

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "total": self.total,
            "proxy_id": self.proxy_id,
            "proxy": self.proxy,
            "mode": self.mode.value,
            "type": self.proxy_type,
            "classification": self.classification.value,
            "selected": self.selected,
            "connected": self.connected,
            "stage": self.stage.value,
            "failure_category": self.failure_category,
            "failure_reason": self.failure_reason,
            "local_port": self.local_port,
            "dns": asdict(self.dns),
            "endpoint_used": self.endpoint_used,
            "http": {
                "success": self.http.success,
                "endpoint_used": self.http.endpoint_used,
                "observed_ip": self.http.observed_ip,
                "success_count": self.http.success_count,
                "failure_count": self.http.failure_count,
                "reason": self.http.reason,
                "results": [item.as_dict() for item in self.http.endpoint_results],
            }
            if self.http
            else None,
            "stage2": self.stage2.as_dict() if self.stage2 else None,
            "log_file": self.log_file,
            "latency": asdict(self.latencies),
        }

    def csv_row(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "proxy_id": self.proxy_id,
            "proxy": self.proxy,
            "type": self.proxy_type,
            "mode": self.mode.value,
            "classification": self.classification.value,
            "selected": str(self.selected),
            "connected": str(self.connected),
            "stage": self.stage.value,
            "failure_category": self.failure_category,
            "failure_reason": self.failure_reason,
            "dns_time_ms": fmt_ms(self.latencies.dns_time_ms),
            "startup_time_ms": fmt_ms(self.latencies.startup_time_ms),
            "socks_ready_time_ms": fmt_ms(self.latencies.socks_ready_time_ms),
            "http_time_ms": fmt_ms(self.latencies.http_time_ms),
            "stage2_time_ms": fmt_ms(self.latencies.stage2_time_ms),
            "total_time_ms": fmt_ms(self.latencies.total_time_ms),
            "resolved_ips": ";".join(self.dns.resolved_ips),
            "endpoint_used": self.endpoint_used,
            "endpoint_success_count": self.http.success_count if self.http else "",
            "stage2_stability_success_count": self.stage2.stability_success_count
            if self.stage2
            else "",
            "stage2_avg_latency_ms": fmt_ms(
                self.stage2.avg_latency_ms if self.stage2 else None
            ),
            "log_file": self.log_file,
        }


@dataclass
class ProxyTestContext:
    index: int
    total: int
    proxy: str
    proxy_id: str
    cfg: AppConfig
    current_stage: Stage = Stage.PARSE
    parsed: Optional[dict[str, Any]] = None
    proxy_type: str = ""
    local_port: Optional[int] = None
    config_file: Optional[str] = None
    process: Optional[asyncio.subprocess.Process] = None
    capture_task: Optional[asyncio.Task[None]] = None
    client_log_tail: str = ""
    per_proxy_log_file: str = ""
    dns: DNSInfo = field(default_factory=DNSInfo)
    latencies: Latencies = field(default_factory=Latencies)

    def set_stage(self, stage: Stage) -> None:
        self.current_stage = stage


class ProxyParseError(ValueError):
    pass


# ---------- small utilities ----------


def configure_utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            with suppress(Exception):
                reconfigure(encoding="utf-8", errors="replace")


def now_perf() -> float:
    return time.perf_counter()


def ms_since(start: float) -> float:
    return (time.perf_counter() - start) * 1000.0


def fmt_ms(value: Optional[float]) -> str:
    if value is None:
        return ""
    return str(int(round(value)))


def short_proxy_id(proxy_url: str) -> str:
    return hashlib.sha1(proxy_url.encode("utf-8", errors="replace")).hexdigest()[:12]


def normalize_input_line(line: str) -> str:
    return line.strip().replace("\ufeff", "")


def truncate(value: str, max_len: int = 170) -> str:
    if len(value) <= max_len:
        return value
    return value[: max_len - 3] + "..."


def pad_b64(s: str) -> str:
    s = s.strip()
    return s + "=" * ((4 - len(s) % 4) % 4)


def b64_decode_urlsafe(s: str) -> bytes:
    return base64.urlsafe_b64decode(pad_b64(s))


def parse_bool_like(v: Optional[str]) -> bool:
    if v is None:
        return False
    return str(v).strip().lower() in {"1", "true", "yes", "on", "tls", "reality"}


def normalize_v2_network(v: Optional[str]) -> str:
    if not v:
        return "tcp"
    v = v.strip().lower()
    mapping = {
        "tcp": "tcp",
        "ws": "ws",
        "websocket": "ws",
        "grpc": "grpc",
        "gun": "grpc",
        "http": "httpupgrade",
        "httpupgrade": "httpupgrade",
        "xhttp": "xhttp",
        "splithttp": "splithttp",
        "h2": "h2",
        "http2": "h2",
        "kcp": "kcp",
        "mkcp": "kcp",
        "quic": "quic",
    }
    return mapping.get(v, v)


def validate_host_port(host: str, port: int) -> tuple[str, int]:
    host = host.strip()
    if not host:
        raise ProxyParseError("missing host")
    if not (1 <= int(port) <= 65535):
        raise ProxyParseError(f"invalid port: {port}")
    return host, int(port)


def parse_host_port(host_port: str, default_port: int = 443) -> tuple[str, int]:
    host_port = host_port.strip()
    # Some shared subscription files contain malformed URLs where the query
    # string leaks into the host:port portion, e.g. host:443?type=tcp.
    # Salvage those instead of throwing an unexpected ValueError.
    host_port = host_port.split("#", 1)[0].split("?", 1)[0].strip()
    if not host_port:
        raise ProxyParseError("missing host")

    if host_port.startswith("["):
        end = host_port.find("]")
        if end == -1:
            raise ProxyParseError("invalid IPv6 host: missing closing bracket")
        host = host_port[1:end]
        rest = host_port[end + 1 :]
        port = int(rest[1:]) if rest.startswith(":") else default_port
        return validate_host_port(host, port)

    if host_port.count(":") == 1:
        host, port_str = host_port.rsplit(":", 1)
        return validate_host_port(host, int(port_str))

    if host_port.count(":") > 1:
        # Raw IPv6 without brackets.
        return validate_host_port(host_port, default_port)

    return validate_host_port(host_port, default_port)


def parse_query(query: str) -> dict[str, str]:
    return dict(
        parse_qsl(query, keep_blank_values=True, encoding="utf-8", errors="replace")
    )


# ---------- parsing ----------


def parse_ss_url(proxy_url: str) -> dict[str, Any]:
    raw = proxy_url.strip()
    rest = raw[5:]
    if not rest:
        raise ProxyParseError("empty Shadowsocks URL")

    if "#" in rest:
        rest, frag = rest.split("#", 1)
        tag = unquote(frag, encoding="utf-8", errors="replace")
    else:
        tag = ""

    if "@" in rest:
        left, right = rest.rsplit("@", 1)
        host, port = parse_host_port(right)
        try:
            decoded = b64_decode_urlsafe(left).decode("utf-8")
        except Exception:
            decoded = unquote(left, encoding="utf-8", errors="replace")
        if ":" not in decoded:
            raise ProxyParseError("Shadowsocks credentials must be method:password")
        method, password = decoded.split(":", 1)
    else:
        try:
            decoded = b64_decode_urlsafe(rest).decode("utf-8")
        except Exception as exc:
            raise ProxyParseError(f"invalid Shadowsocks base64 payload: {exc}") from exc
        if "@" not in decoded:
            raise ProxyParseError("Shadowsocks payload missing @host:port")
        creds, host_port = decoded.rsplit("@", 1)
        if ":" not in creds:
            raise ProxyParseError(
                "Shadowsocks decoded credentials must be method:password"
            )
        method, password = creds.split(":", 1)
        host, port = parse_host_port(host_port)

    method = method.strip()
    if not method:
        raise ProxyParseError("Shadowsocks method is empty")
    if password == "":
        raise ProxyParseError("Shadowsocks password is empty")

    return {
        "type": "ss",
        "raw": raw,
        "host": host,
        "port": port,
        "method": method,
        "password": password,
        "tag": tag,
    }


def parse_vmess_url(proxy_url: str) -> dict[str, Any]:
    parsed = urlparse(proxy_url.strip())
    b64_part = parsed.netloc or parsed.path.lstrip("/")
    if not b64_part:
        raise ProxyParseError("VMess URL missing base64 JSON payload")

    try:
        decoded = b64_decode_urlsafe(b64_part).decode("utf-8")
        data = json.loads(decoded)
    except Exception as exc:
        raise ProxyParseError(
            f"invalid VMess base64/json payload: {type(exc).__name__}: {exc}"
        ) from exc

    network = normalize_v2_network(data.get("net") or data.get("type") or "tcp")
    try:
        port = int(data.get("port", 0))
    except Exception as exc:
        raise ProxyParseError(f"invalid VMess port: {data.get('port')}") from exc

    host = data.get("add") or data.get("host")
    user_id = data.get("id")
    if not host:
        raise ProxyParseError("VMess host/add is missing")
    if not user_id:
        raise ProxyParseError("VMess id is missing")
    validate_host_port(str(host), port)

    tls_field = str(data.get("tls", "")).strip().lower()
    if tls_field in {"tls", "1", "true"}:
        security = "tls"
    elif tls_field == "reality":
        security = "reality"
    else:
        security = "none"

    return {
        "type": "vmess",
        "raw": proxy_url.strip(),
        "host": str(host),
        "port": port,
        "id": str(user_id),
        "aid": int(data.get("aid", 0) or 0),
        "user_security": data.get("scy") or data.get("security") or "auto",
        "network": network,
        "security": security,
        "path": data.get("path", ""),
        "host_header": data.get("host", ""),
        "sni": data.get("sni", ""),
        "alpn": data.get("alpn", ""),
        "service_name": data.get("serviceName", ""),
        "authority": data.get("authority", ""),
        "fp": data.get("fp", ""),
        "pbk": data.get("pbk", ""),
        "sid": data.get("sid", ""),
        "spx": data.get("spx", ""),
        "flow": data.get("flow", ""),
    }


def parse_vless_or_trojan_url(proxy_url: str) -> dict[str, Any]:
    parsed = urlparse(proxy_url.strip())
    scheme = parsed.scheme.lower()
    if scheme not in {"vless", "trojan"}:
        raise ProxyParseError(f"unsupported scheme: {scheme or '<empty>'}")

    netloc = parsed.netloc
    if "@" in netloc:
        userinfo, host_port = netloc.split("@", 1)
    else:
        userinfo, host_port = "", netloc

    userinfo = unquote(userinfo, encoding="utf-8", errors="replace")
    host, port = parse_host_port(host_port)
    params = parse_query(parsed.query)

    network = normalize_v2_network(params.get("type") or params.get("network") or "tcp")
    security = (params.get("security") or "").strip().lower()
    if not security:
        security = "tls" if parse_bool_like(params.get("tls")) else "none"

    result: dict[str, Any] = {
        "type": scheme,
        "raw": proxy_url.strip(),
        "host": host,
        "port": port,
        "network": network,
        "security": security,
        "params": params,
        "tag": unquote(parsed.fragment, encoding="utf-8", errors="replace")
        if parsed.fragment
        else "",
        "sni": params.get("sni") or params.get("serverName") or "",
        "alpn": params.get("alpn", ""),
        "fp": params.get("fp", ""),
        "pbk": params.get("pbk", ""),
        "sid": params.get("sid", ""),
        "spx": params.get("spx", ""),
        "flow": params.get("flow", ""),
        "service_name": params.get("serviceName", ""),
        "authority": params.get("authority", ""),
        "path": unquote(params.get("path", ""), encoding="utf-8", errors="replace"),
        "host_header": params.get("host") or params.get("Host") or "",
        "mode": params.get("mode", ""),
        "header_type": params.get("headerType", ""),
        "seed": params.get("seed", ""),
        "quic_security": params.get("quicSecurity", ""),
        "key": params.get("key", ""),
    }

    if scheme == "vless":
        if not userinfo:
            raise ProxyParseError("VLESS id is missing")
        result["id"] = userinfo
    else:
        if not userinfo:
            raise ProxyParseError("Trojan password is missing")
        result["password"] = userinfo

    return result


def parse_proxy_url(proxy_url: str) -> dict[str, Any]:
    proxy_url = proxy_url.strip()
    if not proxy_url:
        raise ProxyParseError("empty input line")

    scheme = urlparse(proxy_url).scheme.lower()
    if scheme == "ss":
        return parse_ss_url(proxy_url)
    if scheme == "vmess":
        return parse_vmess_url(proxy_url)
    if scheme in {"vless", "trojan"}:
        return parse_vless_or_trojan_url(proxy_url)
    raise ProxyParseError(f"unsupported proxy scheme: {scheme or '<empty>'}")


# ---------- config generation ----------


def build_tls_or_reality_settings(parsed: dict[str, Any]) -> dict[str, Any]:
    security = (parsed.get("security") or "none").lower()
    stream_settings: dict[str, Any] = {
        "network": parsed.get("network", "tcp"),
        "security": security if security in {"tls", "reality"} else "none",
    }

    if security == "tls":
        tls_settings: dict[str, Any] = {"allowInsecure": True}
        server_name = parsed.get("sni") or parsed.get("host")
        if server_name:
            tls_settings["serverName"] = server_name
        alpn = parsed.get("alpn")
        if alpn:
            tls_settings["alpn"] = [
                x.strip() for x in str(alpn).split(",") if x.strip()
            ]
        fp = parsed.get("fp")
        if fp:
            tls_settings["fingerprint"] = fp
        stream_settings["tlsSettings"] = tls_settings

    elif security == "reality":
        reality_settings: dict[str, Any] = {}
        server_name = parsed.get("sni") or parsed.get("host")
        if server_name:
            reality_settings["serverName"] = server_name
        if parsed.get("fp"):
            reality_settings["fingerprint"] = parsed["fp"]
        if parsed.get("pbk"):
            reality_settings["publicKey"] = parsed["pbk"]
        if parsed.get("sid"):
            reality_settings["shortId"] = parsed["sid"]
        if parsed.get("spx"):
            reality_settings["spiderX"] = parsed["spx"]
        stream_settings["realitySettings"] = reality_settings

    return stream_settings


def attach_transport_settings(
    stream_settings: dict[str, Any], parsed: dict[str, Any]
) -> None:
    network = parsed.get("network", "tcp")

    if network == "ws":
        headers = {}
        if parsed.get("host_header"):
            headers["Host"] = parsed["host_header"]
        stream_settings["wsSettings"] = {
            "path": parsed.get("path", "") or "/",
            "headers": headers,
        }

    elif network == "grpc":
        grpc_settings: dict[str, Any] = {}
        if parsed.get("service_name"):
            grpc_settings["serviceName"] = parsed["service_name"]
        if parsed.get("authority"):
            grpc_settings["authority"] = parsed["authority"]
        if parsed.get("mode"):
            grpc_settings["multiMode"] = str(parsed["mode"]).lower() == "multi"
        stream_settings["grpcSettings"] = grpc_settings

    elif network == "httpupgrade":
        headers = {}
        if parsed.get("host_header"):
            headers["Host"] = parsed["host_header"]
        stream_settings["httpupgradeSettings"] = {
            "path": parsed.get("path", "") or "/",
            "host": parsed.get("host_header", ""),
            "headers": headers,
        }

    elif network == "xhttp":
        stream_settings["xhttpSettings"] = {
            "path": parsed.get("path", "") or "/",
            "host": parsed.get("host_header", ""),
            "mode": parsed.get("mode", "") or "auto",
        }

    elif network == "splithttp":
        stream_settings["splithttpSettings"] = {
            "path": parsed.get("path", "") or "/",
            "host": parsed.get("host_header", ""),
        }

    elif network == "h2":
        hosts: list[str] = []
        if parsed.get("host_header"):
            hosts = [
                x.strip() for x in str(parsed["host_header"]).split(",") if x.strip()
            ]
        stream_settings["httpSettings"] = {
            "path": parsed.get("path", "") or "/",
            "host": hosts,
        }

    elif network == "kcp":
        kcp_settings: dict[str, Any] = {}
        if parsed.get("header_type"):
            kcp_settings["header"] = {"type": parsed["header_type"]}
        if parsed.get("seed"):
            kcp_settings["seed"] = parsed["seed"]
        stream_settings["kcpSettings"] = kcp_settings

    elif network == "quic":
        quic_settings: dict[str, Any] = {}
        if parsed.get("quic_security"):
            quic_settings["security"] = parsed["quic_security"]
        if parsed.get("key"):
            quic_settings["key"] = parsed["key"]
        if parsed.get("header_type"):
            quic_settings["header"] = {"type": parsed["header_type"]}
        stream_settings["quicSettings"] = quic_settings


def generate_xray_config(
    parsed: dict[str, Any], local_port: int, debug: bool
) -> dict[str, Any]:
    proxy_type = parsed["type"]

    if proxy_type == "vless":
        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": parsed["host"],
                        "port": parsed["port"],
                        "users": [
                            {
                                "id": parsed["id"],
                                "encryption": "none",
                                **(
                                    {"flow": parsed["flow"]}
                                    if parsed.get("flow")
                                    else {}
                                ),
                            }
                        ],
                    }
                ]
            },
        }

    elif proxy_type == "vmess":
        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [
                    {
                        "address": parsed["host"],
                        "port": parsed["port"],
                        "users": [
                            {
                                "id": parsed["id"],
                                "alterId": parsed.get("aid", 0),
                                "security": parsed.get("user_security", "auto"),
                            }
                        ],
                    }
                ]
            },
        }

    elif proxy_type == "trojan":
        outbound = {
            "protocol": "trojan",
            "settings": {
                "servers": [
                    {
                        "address": parsed["host"],
                        "port": parsed["port"],
                        "password": parsed["password"],
                        **({"flow": parsed["flow"]} if parsed.get("flow") else {}),
                    }
                ]
            },
        }

    else:
        raise ValueError(f"unsupported xray protocol: {proxy_type}")

    stream_settings = build_tls_or_reality_settings(parsed)
    attach_transport_settings(stream_settings, parsed)
    outbound["streamSettings"] = stream_settings

    return {
        "log": {"loglevel": "debug" if debug else "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "protocol": "socks",
                "listen": LOCAL_HOST,
                "port": local_port,
                "settings": {"auth": "noauth", "udp": False},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
            }
        ],
        "outbounds": [
            outbound,
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "blocked"},
        ],
    }


def generate_ss_config(parsed: dict[str, Any], local_port: int) -> dict[str, Any]:
    return {
        "server": parsed["host"],
        "server_port": parsed["port"],
        "password": parsed["password"],
        "method": parsed["method"],
        "local_address": LOCAL_HOST,
        "local_port": local_port,
        "timeout": 10,
        "fast_open": False,
        "mode": "tcp_only",
    }


def write_json_config(config: dict[str, Any], prefix: str) -> str:
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8", errors="replace", newline="\n") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)
        f.write("\n")
    return path


def build_client(
    parsed: dict[str, Any], local_port: int, cfg: AppConfig
) -> tuple[list[str], str]:
    proxy_type = parsed["type"]
    if proxy_type in {"vless", "vmess", "trojan"}:
        config = generate_xray_config(parsed, local_port, cfg.debug)
        config_path = write_json_config(config, "xray_proxy_")
        return [cfg.xray_bin, "run", "-c", config_path], config_path

    if proxy_type == "ss":
        config = generate_ss_config(parsed, local_port)
        config_path = write_json_config(config, "ss_proxy_")
        return [cfg.ss_bin, "-c", config_path], config_path

    raise ValueError(f"unsupported proxy type: {proxy_type}")


# ---------- DNS diagnostics ----------


def _family_name(family: socket.AddressFamily) -> str:
    if family == socket.AF_INET:
        return "IPv4"
    if family == socket.AF_INET6:
        return "IPv6"
    return str(family)


def _resolve_sync(host: str, port: int) -> tuple[list[str], list[str]]:
    host_for_dns = host.strip("[]")
    try:
        ipaddress.ip_address(host_for_dns)
    except ValueError:
        try:
            host_for_dns = host_for_dns.encode("idna").decode("ascii")
        except Exception:
            pass

    infos = socket.getaddrinfo(host_for_dns, port, type=socket.SOCK_STREAM)
    ips: list[str] = []
    families: list[str] = []
    seen_ips: set[str] = set()
    seen_families: set[str] = set()
    for family, _type, _proto, _canonname, sockaddr in infos:
        ip = str(sockaddr[0])
        fam = _family_name(family)
        if ip not in seen_ips:
            seen_ips.add(ip)
            ips.append(ip)
        if fam not in seen_families:
            seen_families.add(fam)
            families.append(fam)
    return ips, families


async def resolve_host(host: str, port: int) -> DNSInfo:
    started = now_perf()
    try:
        ips, families = await asyncio.to_thread(_resolve_sync, host, port)
        return DNSInfo(
            host=host,
            resolved_ips=ips,
            families=families,
            dns_time_ms=ms_since(started),
        )
    except Exception as exc:
        return DNSInfo(
            host=host,
            dns_time_ms=ms_since(started),
            error=f"{type(exc).__name__}: {exc}",
        )


# ---------- process handling ----------


class ClientLogBuffer:
    def __init__(self, max_chars: int = 65536) -> None:
        self.max_chars = max_chars
        self.parts: deque[str] = deque()
        self.size = 0

    def append(self, text: str) -> None:
        if not text:
            return
        self.parts.append(text)
        self.size += len(text)
        while self.size > self.max_chars and self.parts:
            removed = self.parts.popleft()
            self.size -= len(removed)

    def text(self) -> str:
        return "".join(self.parts)[-self.max_chars :]


async def capture_process_output(
    process: asyncio.subprocess.Process,
    buffer: ClientLogBuffer,
    per_proxy_log_file: str = "",
) -> None:
    if process.stdout is None:
        return

    fh = None
    try:
        if per_proxy_log_file:
            Path(per_proxy_log_file).parent.mkdir(parents=True, exist_ok=True)
            fh = open(
                per_proxy_log_file, "a", encoding="utf-8", errors="replace", newline=""
            )
        while True:
            chunk = await process.stdout.readline()
            if not chunk:
                break
            text = chunk.decode("utf-8", errors="replace")
            buffer.append(text)
            if fh:
                fh.write(text)
                fh.flush()
    finally:
        if fh:
            with suppress(Exception):
                fh.close()


async def launch_client(
    client_cmd: list[str], ctx: ProxyTestContext, logger: logging.Logger
) -> asyncio.subprocess.Process:
    if ctx.per_proxy_log_file:
        Path(ctx.per_proxy_log_file).parent.mkdir(parents=True, exist_ok=True)
        with open(
            ctx.per_proxy_log_file,
            "a",
            encoding="utf-8",
            errors="replace",
            newline="\n",
        ) as log_fh:
            log_fh.write(f"\n--- launching: {' '.join(client_cmd)} ---\n")

    logger.debug("[%s] launching client: %s", ctx.proxy_id, " ".join(client_cmd))
    return await asyncio.create_subprocess_exec(
        *client_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )


async def terminate_process(process: Optional[asyncio.subprocess.Process]) -> None:
    if process is None or process.returncode is not None:
        return
    try:
        process.terminate()
        await asyncio.wait_for(process.wait(), timeout=2)
    except Exception:
        with suppress(Exception):
            process.kill()
            await asyncio.wait_for(process.wait(), timeout=2)


async def finish_capture_task(capture_task: Optional[asyncio.Task[None]]) -> None:
    if capture_task is None:
        return
    try:
        await asyncio.wait_for(capture_task, timeout=2)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        capture_task.cancel()
        with suppress(BaseException):
            await capture_task
    except Exception:
        capture_task.cancel()
        with suppress(BaseException):
            await capture_task


@dataclass
class SocksReadyResult:
    ready: bool
    stage: Stage
    category: FailureCategory
    reason: str
    elapsed_ms: float


async def wait_for_local_socks_ready(
    process: asyncio.subprocess.Process,
    host: str,
    port: int,
    timeout: float,
) -> SocksReadyResult:
    started = now_perf()
    deadline = asyncio.get_running_loop().time() + timeout

    while asyncio.get_running_loop().time() < deadline:
        if process.returncode is not None:
            return SocksReadyResult(
                ready=False,
                stage=Stage.CLIENT_START,
                category=FailureCategory.CLIENT_START_ERROR,
                reason=f"client exited early with code {process.returncode}",
                elapsed_ms=ms_since(started),
            )

        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=0.75
            )
            writer.close()
            await writer.wait_closed()
            return SocksReadyResult(
                ready=True,
                stage=Stage.WAIT_FOR_LOCAL_SOCKS,
                category=FailureCategory.UNKNOWN_ERROR,
                reason="",
                elapsed_ms=ms_since(started),
            )
        except Exception:
            await asyncio.sleep(READINESS_CHECK_INTERVAL)

    return SocksReadyResult(
        ready=False,
        stage=Stage.WAIT_FOR_LOCAL_SOCKS,
        category=FailureCategory.TIMEOUT_ERROR,
        reason=f"timeout_stage={Stage.WAIT_FOR_LOCAL_SOCKS.value} elapsed={timeout:.2f}s local socks not ready",
        elapsed_ms=ms_since(started),
    )


# ---------- HTTP validation ----------


def maybe_valid_ip(value: str) -> str:
    candidate = value.strip().strip("'\" ,")
    if not candidate:
        return ""
    candidate = candidate.split(",")[0].strip()
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return ""


def extract_ip_from_response(endpoint: str, text: str) -> str:
    stripped = text.strip()
    if not stripped:
        return ""

    try:
        data = json.loads(stripped)
        if isinstance(data, dict):
            for key in ("ip", "origin"):
                if key in data:
                    found = maybe_valid_ip(str(data[key]))
                    if found:
                        return found
    except Exception:
        pass

    if "cdn-cgi/trace" in endpoint:
        for line in stripped.splitlines():
            if line.startswith("ip="):
                return maybe_valid_ip(line.split("=", 1)[1])

    first_token = stripped.split()[0] if stripped.split() else ""
    return maybe_valid_ip(first_token)


async def test_single_endpoint(
    session: aiohttp.ClientSession,
    endpoint: str,
    require_ip: bool = True,
    verify_ssl: bool = True,
) -> EndpointResult:
    started = now_perf()
    try:
        request_kwargs: dict[str, Any] = {
            "allow_redirects": True,
            "headers": {"User-Agent": "proxy-probe/1.0"},
        }
        if endpoint.lower().startswith("https://") and not verify_ssl:
            # For proxy screening we care whether bytes can pass through the
            # tunnel.  Broken local CA stores, interception, or odd proxy paths
            # should not automatically hide weak-but-usable configs.
            request_kwargs["ssl"] = False

        async with session.get(endpoint, **request_kwargs) as resp:
            text = await resp.text(errors="replace")
            latency_ms = ms_since(started)
            observed_ip = extract_ip_from_response(endpoint, text)
            if resp.status not in {200, 204}:
                return EndpointResult(
                    endpoint=endpoint,
                    success=False,
                    latency_ms=latency_ms,
                    status=resp.status,
                    observed_ip=observed_ip,
                    error=f"HTTP status {resp.status}",
                )
            if require_ip and resp.status == 200 and not observed_ip:
                snippet = text.strip().replace("\n", " ")[:160]
                return EndpointResult(
                    endpoint=endpoint,
                    success=False,
                    latency_ms=latency_ms,
                    status=resp.status,
                    error=f"response validation failed; could not extract IP; body={snippet!r}",
                )
            if (
                not require_ip
                and resp.status == 200
                and not observed_ip
                and not text.strip()
            ):
                return EndpointResult(
                    endpoint=endpoint,
                    success=False,
                    latency_ms=latency_ms,
                    status=resp.status,
                    error="empty response",
                )
            return EndpointResult(
                endpoint=endpoint,
                success=True,
                latency_ms=latency_ms,
                status=resp.status,
                observed_ip=observed_ip,
            )
    except Exception as exc:
        return EndpointResult(
            endpoint=endpoint,
            success=False,
            latency_ms=ms_since(started),
            error=f"{type(exc).__name__}: {exc}",
        )


async def run_http_tests_through_socks(
    local_port: int,
    cfg: AppConfig,
    *,
    test_all: bool,
    logger: logging.Logger,
) -> HTTPStageResult:
    started = now_perf()
    connector = ProxyConnector.from_url(f"socks5://{LOCAL_HOST}:{local_port}")
    timeout = aiohttp.ClientTimeout(total=cfg.test_timeout)
    endpoint_results: list[EndpointResult] = []
    first_success_endpoint = ""
    first_success_ip = ""

    # Fast and balanced modes intentionally use the old tester's lenient
    # definition of "connected": HTTP 200/204 with either a valid IP response
    # or any non-empty body.  This protects weak but usable configs from being
    # discarded just because a public IP endpoint behaves oddly.
    require_ip = cfg.mode in {Mode.STRICT, Mode.DIAGNOSE}
    verify_ssl = cfg.mode in {Mode.STRICT, Mode.DIAGNOSE}

    async with aiohttp.ClientSession(
        connector=connector, timeout=timeout, trust_env=False
    ) as session:
        for endpoint in cfg.test_urls:
            result = await test_single_endpoint(
                session, endpoint, require_ip=require_ip, verify_ssl=verify_ssl
            )
            endpoint_results.append(result)
            if result.success:
                logger.debug(
                    "HTTP endpoint success endpoint=%s latency_ms=%s ip=%s",
                    endpoint,
                    fmt_ms(result.latency_ms),
                    result.observed_ip,
                )
                if not first_success_endpoint:
                    first_success_endpoint = result.endpoint
                    first_success_ip = result.observed_ip
                if not test_all:
                    break
            else:
                logger.debug(
                    "HTTP endpoint failed endpoint=%s latency_ms=%s status=%s error=%s",
                    endpoint,
                    fmt_ms(result.latency_ms),
                    result.status,
                    result.error,
                )

    elapsed_ms = ms_since(started)
    if first_success_endpoint:
        return HTTPStageResult(
            success=True,
            endpoint_used=first_success_endpoint,
            observed_ip=first_success_ip,
            endpoint_results=endpoint_results,
            stage=Stage.RESPONSE_VALIDATION,
            category=FailureCategory.UNKNOWN_ERROR,
            reason="",
            elapsed_ms=elapsed_ms,
        )

    if not endpoint_results:
        return HTTPStageResult(
            success=False,
            stage=Stage.HTTP_TEST,
            category=FailureCategory.HTTP_ERROR,
            reason="no HTTP endpoints configured",
            elapsed_ms=elapsed_ms,
        )

    errors = [r.error for r in endpoint_results if r.error]
    any_timeout = any(
        "TimeoutError" in r.error or "timeout" in r.error.lower()
        for r in endpoint_results
    )
    any_validation_failure = any(
        "response validation failed" in r.error for r in endpoint_results
    )
    any_transport_error = any(r.status is None and r.error for r in endpoint_results)
    last_error = errors[-1] if errors else "all endpoints failed"

    if any_timeout and not any_validation_failure:
        category = FailureCategory.TIMEOUT_ERROR
        stage = Stage.HTTP_TEST
    elif any_transport_error and not any_validation_failure:
        category = FailureCategory.HTTP_ERROR
        stage = Stage.HTTP_TEST
    else:
        category = FailureCategory.HTTP_ERROR
        stage = Stage.RESPONSE_VALIDATION

    return HTTPStageResult(
        success=False,
        endpoint_results=endpoint_results,
        stage=stage,
        category=category,
        reason=f"all endpoints failed; last_error={last_error}",
        elapsed_ms=elapsed_ms,
    )


# ---------- Stage2 checks ----------


def make_session(local_port: int, timeout_seconds: float) -> aiohttp.ClientSession:
    connector = ProxyConnector.from_url(f"socks5://{LOCAL_HOST}:{local_port}")
    timeout = aiohttp.ClientTimeout(total=timeout_seconds)
    return aiohttp.ClientSession(connector=connector, timeout=timeout, trust_env=False)


async def stage2_dns_over_proxy(local_port: int) -> tuple[bool, str]:
    try:
        async with make_session(local_port, 8.0) as session:
            async with session.get(STAGE2_DNS_TEST_URL, allow_redirects=True) as resp:
                if resp.status != 200:
                    return False, f"status={resp.status}"
                try:
                    data = await resp.json()
                except Exception as exc:
                    return False, f"json_error={type(exc).__name__}: {exc}"
                if not isinstance(data, dict):
                    return False, "response_not_dict"
                if "Status" in data and int(data.get("Status", 1)) != 0:
                    return False, f"dns_status={data.get('Status')}"
                if not any(k in data for k in STAGE2_DNS_EXPECTED_KEYS):
                    return False, "missing_dns_keys"
                if "Answer" not in data:
                    return False, "no_answer"
                return True, "dns_ok"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


async def stage2_https(local_port: int) -> tuple[bool, str, Optional[float]]:
    started = now_perf()
    try:
        async with make_session(local_port, 10.0) as session:
            async with session.get(STAGE2_HTTPS_TEST_URL, allow_redirects=True) as resp:
                text = await resp.text(errors="replace")
                latency_ms = ms_since(started)
                if resp.status != 200:
                    return False, f"status={resp.status}", latency_ms
                if not text.strip():
                    return False, "empty_body", latency_ms
                return True, "https_ok", latency_ms
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}", ms_since(started)


async def stage2_multi_domain(local_port: int) -> tuple[bool, str, int, int]:
    failures: list[str] = []
    success_count = 0
    try:
        async with make_session(local_port, 12.0) as session:
            for url in STAGE2_MULTI_DOMAIN_URLS:
                try:
                    async with session.get(url, allow_redirects=True) as resp:
                        _ = await resp.read()
                        if resp.status in {200, 204}:
                            success_count += 1
                        else:
                            failures.append(f"{url} status={resp.status}")
                except Exception as exc:
                    failures.append(f"{url} {type(exc).__name__}: {exc}")
        ok = success_count >= 1
        if ok:
            reason = (
                f"multi_domain_success={success_count}/{len(STAGE2_MULTI_DOMAIN_URLS)}"
            )
        else:
            reason = " | ".join(failures[:3]) or "no domain succeeded"
        return ok, reason, success_count, len(STAGE2_MULTI_DOMAIN_URLS)
    except Exception as exc:
        return (
            False,
            f"{type(exc).__name__}: {exc}",
            success_count,
            len(STAGE2_MULTI_DOMAIN_URLS),
        )


async def stage2_stability(local_port: int) -> tuple[bool, str, int, Optional[float]]:
    latencies: list[float] = []
    success_count = 0
    try:
        async with make_session(local_port, 14.0) as session:
            for i in range(STAGE2_STABILITY_ROUNDS):
                url = STAGE2_STABILITY_URLS[i % len(STAGE2_STABILITY_URLS)]
                started = now_perf()
                try:
                    async with session.get(url, allow_redirects=True) as resp:
                        _ = await resp.read()
                        if resp.status in {200, 204}:
                            latency_ms = ms_since(started)
                            latencies.append(latency_ms)
                            success_count += 1
                except Exception:
                    pass
        avg_latency = sum(latencies) / len(latencies) if latencies else None
        if success_count < STAGE2_MIN_STABILITY_SUCCESSES:
            return (
                False,
                f"success_count={success_count}/{STAGE2_STABILITY_ROUNDS}",
                success_count,
                avg_latency,
            )
        return True, "stability_ok", success_count, avg_latency
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}", success_count, None


async def run_stage2_checks(local_port: int) -> Stage2CheckResult:
    started = now_perf()
    result = Stage2CheckResult()

    result.dns_ok, result.dns_reason = await stage2_dns_over_proxy(local_port)
    result.https_ok, result.https_reason, https_latency = await stage2_https(local_port)
    multi_ok, multi_reason, multi_count, multi_total = await stage2_multi_domain(
        local_port
    )
    result.multi_domain_ok = multi_ok
    result.multi_domain_reason = multi_reason
    result.multi_domain_success_count = multi_count
    result.multi_domain_total = multi_total
    stability_ok, stability_reason, success_count, avg_latency = await stage2_stability(
        local_port
    )
    result.stability_ok = stability_ok
    result.stability_reason = stability_reason
    result.stability_success_count = success_count
    result.avg_latency_ms = avg_latency if avg_latency is not None else https_latency
    result.elapsed_ms = ms_since(started)
    return result


# ---------- client log classification ----------


@dataclass(frozen=True)
class ClientDiagnostic:
    category: FailureCategory
    reason: str
    matched_line: str


CLIENT_LOG_PATTERNS: list[tuple[FailureCategory, str, str]] = [
    (
        FailureCategory.REALITY_ERROR,
        r"(?i)(reality.*(fail|error|invalid)|public\s*key|short\s*id|shortid|spiderx)",
        "Reality configuration/startup error",
    ),
    (
        FailureCategory.TLS_ERROR,
        r"(?i)(tls.*handshake|handshake.*tls|x509|certificate|first record does not look like a tls handshake)",
        "TLS handshake/certificate error",
    ),
    (
        FailureCategory.DNS_ERROR,
        r"(?i)(no such host|dns.*(fail|error)|server misbehaving|lookup .+ failed)",
        "client-side DNS error",
    ),
    (
        FailureCategory.TIMEOUT_ERROR,
        r"(?i)(i/o timeout|dial timeout|context deadline exceeded|deadline exceeded|operation timed out|connect timeout)",
        "dial/connect timeout",
    ),
    (
        FailureCategory.HTTP_ERROR,
        r"(?i)(connection refused|connection reset|broken pipe|server disconnected|unexpected eof)",
        "remote connection error",
    ),
    (
        FailureCategory.SOCKS_ERROR,
        r"(?i)(address already in use|failed to listen|bind:|listen tcp)",
        "local SOCKS/listen error",
    ),
    (
        FailureCategory.CLIENT_START_ERROR,
        r"(?i)(failed to start|panic:|fatal|permission denied|exec format error|unknown command|invalid config)",
        "client startup/config error",
    ),
]


def classify_client_log_text(text: str) -> Optional[ClientDiagnostic]:
    if not text:
        return None
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for category, pattern, reason in CLIENT_LOG_PATTERNS:
        regex = re.compile(pattern)
        for line in reversed(lines):
            if regex.search(line):
                return ClientDiagnostic(
                    category=category, reason=reason, matched_line=line[-500:]
                )
    return None


def enhance_failure_from_client_log(
    text: str,
    category: FailureCategory,
    reason: str,
) -> tuple[FailureCategory, str]:
    diagnostic = classify_client_log_text(text)
    if diagnostic is None:
        return category, reason
    enhanced_reason = (
        f"{reason} | client_log={diagnostic.reason}: {diagnostic.matched_line}"
    )
    return diagnostic.category, enhanced_reason


# ---------- classification ----------


def is_connected_class(value: Classification) -> bool:
    return value in CONNECTED_CLASSES


def selected_for_output(mode: Mode, classification: Classification) -> bool:
    if mode == Mode.STRICT:
        return classification == Classification.GOOD
    return classification in CONNECTED_CLASSES


def classify_after_http(
    ctx: ProxyTestContext, http: HTTPStageResult
) -> tuple[Classification, FailureCategory, str, Stage]:
    if http.success:
        if http.elapsed_ms > ctx.cfg.slow_threshold_ms:
            return (
                Classification.SLOW_BUT_WORKING,
                FailureCategory.UNKNOWN_ERROR,
                "",
                Stage.RESPONSE_VALIDATION,
            )
        if ctx.cfg.mode == Mode.DIAGNOSE and http.failure_count > 0:
            return (
                Classification.PARTIAL,
                FailureCategory.UNKNOWN_ERROR,
                "",
                Stage.RESPONSE_VALIDATION,
            )
        return (
            Classification.GOOD,
            FailureCategory.UNKNOWN_ERROR,
            "",
            Stage.RESPONSE_VALIDATION,
        )

    reason = http.reason or "all endpoints failed"
    category = http.category
    if category == FailureCategory.TIMEOUT_ERROR:
        return Classification.UNKNOWN, category, reason, http.stage
    return Classification.UNKNOWN, category, reason, http.stage


def classify_after_stage2(
    ctx: ProxyTestContext, http: HTTPStageResult, stage2: Stage2CheckResult
) -> tuple[Classification, FailureCategory, str, Stage]:
    # This is deliberately soft. Stage2 failures after a basic HTTP success mean
    # partial/slow/unstable, not automatically dead.
    avg_latency = (
        stage2.avg_latency_ms if stage2.avg_latency_ms is not None else http.elapsed_ms
    )

    if (
        stage2.https_ok
        and stage2.multi_domain_success_count >= 1
        and stage2.stability_success_count >= STAGE2_MIN_STABILITY_SUCCESSES
    ):
        if avg_latency > ctx.cfg.slow_threshold_ms:
            return (
                Classification.SLOW_BUT_WORKING,
                FailureCategory.UNKNOWN_ERROR,
                "",
                Stage.STAGE2_STABILITY,
            )
        return (
            Classification.GOOD,
            FailureCategory.UNKNOWN_ERROR,
            "",
            Stage.STAGE2_STABILITY,
        )

    if (
        stage2.stability_success_count > 0
        and stage2.stability_success_count < STAGE2_MIN_STABILITY_SUCCESSES
    ):
        return (
            Classification.UNSTABLE,
            FailureCategory.UNKNOWN_ERROR,
            f"stage2_unstable stability={stage2.stability_success_count}/{stage2.stability_rounds}; {stage2.stability_reason}",
            Stage.STAGE2_STABILITY,
        )

    if stage2.multi_domain_success_count > 0 or stage2.https_ok or stage2.dns_ok:
        return (
            Classification.PARTIAL,
            FailureCategory.UNKNOWN_ERROR,
            "stage2_partial "
            f"dns={stage2.dns_ok} https={stage2.https_ok} "
            f"multi={stage2.multi_domain_success_count}/{stage2.multi_domain_total} "
            f"stability={stage2.stability_success_count}/{stage2.stability_rounds}",
            Stage.STAGE2_MULTI_DOMAIN,
        )

    return (
        Classification.PARTIAL,
        FailureCategory.UNKNOWN_ERROR,
        "basic HTTP worked but all strict Stage2 checks failed",
        Stage.STAGE2_STABILITY,
    )


# ---------- port allocation ----------


class PortAllocator:
    def __init__(self) -> None:
        self._reserved: set[int] = set()
        self._lock = asyncio.Lock()

    async def acquire(self) -> int:
        async with self._lock:
            for _ in range(100):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind((LOCAL_HOST, 0))
                    port = int(s.getsockname()[1])
                if port not in self._reserved:
                    self._reserved.add(port)
                    return port
            raise RuntimeError("could not allocate a unique local port")

    async def release(self, port: Optional[int]) -> None:
        if port is None:
            return
        async with self._lock:
            self._reserved.discard(port)


# ---------- output ----------


class OutputManager:
    def __init__(self, cfg: AppConfig) -> None:
        self.cfg = cfg
        self._lock = asyncio.Lock()
        mode = "a" if cfg.append else "w"
        cfg.output.parent.mkdir(parents=True, exist_ok=True)
        self._output_fh = open(
            cfg.output, mode, encoding="utf-8", errors="replace", newline="\n"
        )
        self._failed_fh = self._open_optional(cfg.save_failed, mode)
        self._unknown_fh = self._open_optional(cfg.save_unknown, mode)
        self._jsonl_fh = self._open_optional(cfg.jsonl_path, mode)
        self._csv_fh = None
        self._csv_writer: Optional[csv.DictWriter[str]] = None
        self._bucket_fhs: dict[Classification, Any] = {}

        if cfg.csv_path:
            cfg.csv_path.parent.mkdir(parents=True, exist_ok=True)
            csv_exists = (
                cfg.append and cfg.csv_path.exists() and cfg.csv_path.stat().st_size > 0
            )
            self._csv_fh = open(
                cfg.csv_path, mode, encoding="utf-8", errors="replace", newline=""
            )
            self._csv_writer = csv.DictWriter(self._csv_fh, fieldnames=CSV_COLUMNS)
            if not csv_exists:
                self._csv_writer.writeheader()
                self._csv_fh.flush()

        if cfg.save_buckets:
            bucket_dir = cfg.output.parent
            bucket_dir.mkdir(parents=True, exist_ok=True)
            for classification in Classification:
                path = bucket_dir / f"{classification.value.lower()}.txt"
                self._bucket_fhs[classification] = open(
                    path, mode, encoding="utf-8", errors="replace", newline="\n"
                )

    def _open_optional(self, path: Optional[Path], mode: str):
        if path is None:
            return None
        path.parent.mkdir(parents=True, exist_ok=True)
        return open(path, mode, encoding="utf-8", errors="replace", newline="\n")

    async def write_result(self, result: TestResult) -> None:
        async with self._lock:
            if result.selected and not self.cfg.sort_ping:
                self._output_fh.write(result.proxy + "\n")
                self._output_fh.flush()
                self._maybe_fsync(self._output_fh)

            if self._failed_fh and result.classification in {
                Classification.DEAD,
                Classification.PARSE_FAILED,
            }:
                self._failed_fh.write(result.proxy + "\n")
                self._failed_fh.flush()
                self._maybe_fsync(self._failed_fh)

            if self._unknown_fh and result.classification == Classification.UNKNOWN:
                self._unknown_fh.write(result.proxy + "\n")
                self._unknown_fh.flush()
                self._maybe_fsync(self._unknown_fh)

            bucket = self._bucket_fhs.get(result.classification)
            if bucket:
                bucket.write(result.proxy + "\n")
                bucket.flush()
                self._maybe_fsync(bucket)

            if self._jsonl_fh:
                self._jsonl_fh.write(
                    json.dumps(result.to_json_dict(), ensure_ascii=False) + "\n"
                )
                self._jsonl_fh.flush()
                self._maybe_fsync(self._jsonl_fh)

            if self._csv_writer and self._csv_fh:
                self._csv_writer.writerow(result.csv_row())
                self._csv_fh.flush()
                self._maybe_fsync(self._csv_fh)

    def _maybe_fsync(self, fh: Any) -> None:
        if not self.cfg.fsync_output:
            return
        with suppress(Exception):
            os.fsync(fh.fileno())

    def close(self) -> None:
        handles = [
            self._output_fh,
            self._failed_fh,
            self._unknown_fh,
            self._jsonl_fh,
            self._csv_fh,
        ]
        handles.extend(self._bucket_fhs.values())
        for fh in handles:
            if fh:
                with suppress(Exception):
                    fh.close()


# ---------- logging and console ----------


ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m",
    "bright_red": "\033[91m",
    "bright_green": "\033[92m",
    "bright_yellow": "\033[93m",
    "bright_blue": "\033[94m",
    "bright_magenta": "\033[95m",
    "bright_cyan": "\033[96m",
    "white_on_blue": "\033[1;37;44m",
    "white_on_green": "\033[1;37;42m",
    "white_on_red": "\033[1;37;41m",
    "black_on_yellow": "\033[1;30;43m",
    "white_on_magenta": "\033[1;37;45m",
}

CLASS_COLORS = {
    Classification.GOOD: "bright_green",
    Classification.SLOW_BUT_WORKING: "bright_yellow",
    Classification.PARTIAL: "bright_cyan",
    Classification.UNSTABLE: "bright_magenta",
    Classification.UNKNOWN: "bright_blue",
    Classification.DEAD: "bright_red",
    Classification.PARSE_FAILED: "bright_red",
}


def setup_file_logger(cfg: AppConfig) -> logging.Logger:
    logger = logging.getLogger("proxy-probe")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG if cfg.debug else logging.INFO)
    logger.propagate = False
    if cfg.log_file:
        cfg.log_file.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(
            cfg.log_file,
            mode="a" if cfg.append else "w",
            encoding="utf-8",
            errors="replace",
        )
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(
            logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s")
        )
        logger.addHandler(handler)
    else:
        logger.addHandler(logging.NullHandler())
    return logger


class ConsoleReporter:
    def __init__(self, cfg: AppConfig) -> None:
        self.cfg = cfg
        self.enabled = not cfg.quiet
        self.use_color = self.enabled and not cfg.no_color and sys.stderr.isatty()
        self._last_progress_done = 0

    def color(self, text: str, name: str) -> str:
        if not self.use_color:
            return text
        return f"{ANSI.get(name, '')}{text}{ANSI['reset']}"

    def classification(self, value: Classification) -> str:
        return self.color(value.value, CLASS_COLORS.get(value, "white"))

    def start(self, total: int) -> None:
        if not self.enabled:
            return
        tag = self.color(" START ", "white_on_blue")
        run_mode = "ping-only" if self.cfg.sort_ping_only else self.cfg.mode.value
        print(
            f"{tag} mode={run_mode} total={total} threads={self.cfg.threads} "
            f"output={self.cfg.output} summary={self.cfg.summary_path} log_file={self.cfg.log_file or 'disabled'}",
            file=sys.stderr,
            flush=True,
        )

    def progress(
        self,
        stats: "ProgressStats",
        last_result: Optional[TestResult] = None,
        force: bool = False,
    ) -> None:
        if not self.enabled:
            return
        if not force and stats.done == self._last_progress_done:
            return
        self._last_progress_done = stats.done
        tag = self.color(" PROGRESS ", "white_on_blue")
        parts = [
            f"{stats.done}/{stats.total}",
            f"selected={stats.selected}",
            f"connected={stats.connected}",
            f"good={stats.class_counts[Classification.GOOD]}",
            f"slow={stats.class_counts[Classification.SLOW_BUT_WORKING]}",
            f"partial={stats.class_counts[Classification.PARTIAL]}",
            f"unstable={stats.class_counts[Classification.UNSTABLE]}",
            f"unknown={stats.class_counts[Classification.UNKNOWN]}",
            f"dead={stats.class_counts[Classification.DEAD] + stats.class_counts[Classification.PARSE_FAILED]}",
            f"active={stats.active}",
            f"rate={stats.connected_rate():.2f}%",
            f"avg={stats.avg_latency_s():.2f}s",
            f"elapsed={stats.elapsed_s():.1f}s",
        ]
        print(f"{tag} " + " | ".join(parts), file=sys.stderr, flush=True)
        if last_result is not None:
            last = (
                f"last=config {last_result.index}/{last_result.total}: status={self.classification(last_result.classification)} "
                f"stage={last_result.stage.value} reason={truncate(last_result.failure_reason or '-', 120)}"
            )
            print(" " * 11 + last, file=sys.stderr, flush=True)

    def result_line(self, result: TestResult) -> None:
        if not self.enabled:
            return
        # Avoid flooding huge runs. Show selected/connected results and occasional important failures.
        if not result.selected and result.classification not in {
            Classification.UNKNOWN,
            Classification.PARSE_FAILED,
        }:
            return
        tag = self.classification(result.classification)
        latency = fmt_ms(result.latencies.total_time_ms) or "?"
        print(
            f"testing config {result.index}/{result.total}: status={tag} stage={result.stage.value} "
            f"latency={latency}ms reason={truncate(result.failure_reason or '-', 110)}",
            file=sys.stderr,
            flush=True,
        )

    def final(self, summary: dict[str, Any]) -> None:
        if not self.enabled:
            return
        tag = self.color(" FINAL ", "white_on_green")
        print(
            f"{tag} total={summary['total']} selected={summary['selected']} connected={summary['connected']} "
            f"failed={summary['failed']} unknown={summary['unknown']} success_rate={summary['connected_rate']:.2f}% "
            f"elapsed={summary['elapsed_seconds']:.1f}s",
            file=sys.stderr,
            flush=True,
        )
        if summary.get("top_failure_categories"):
            tag2 = self.color(" TOP FAILURES ", "white_on_magenta")
            cats = ", ".join(
                f"{k}={v}"
                for k, v in list(summary["top_failure_categories"].items())[:5]
            )
            print(f"{tag2} {cats}", file=sys.stderr, flush=True)


# ---------- progress stats ----------


@dataclass
class ProgressStats:
    total: int
    done: int = 0
    selected: int = 0
    connected: int = 0
    failed: int = 0
    unknown: int = 0
    active: int = 0
    total_latency_ms: float = 0.0
    class_counts: dict[Classification, int] = field(
        default_factory=lambda: defaultdict(int)
    )
    category_counts: Counter[str] = field(default_factory=Counter)
    reason_counts: Counter[str] = field(default_factory=Counter)
    started: float = field(default_factory=now_perf)

    def connected_rate(self) -> float:
        return (self.connected / self.done * 100.0) if self.done else 0.0

    def avg_latency_s(self) -> float:
        return (self.total_latency_ms / self.done / 1000.0) if self.done else 0.0

    def elapsed_s(self) -> float:
        return time.perf_counter() - self.started


async def progress_reporter(
    stats: ProgressStats,
    stats_lock: asyncio.Lock,
    stop_event: asyncio.Event,
    reporter: ConsoleReporter,
    interval: float,
    get_last_result,
) -> None:
    while not stop_event.is_set():
        async with stats_lock:
            reporter.progress(stats, get_last_result())
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            continue


# ---------- test pipeline ----------


def make_result(
    ctx: ProxyTestContext,
    *,
    classification: Classification,
    stage: Stage,
    category: FailureCategory = FailureCategory.UNKNOWN_ERROR,
    reason: str = "",
    http: Optional[HTTPStageResult] = None,
    stage2: Optional[Stage2CheckResult] = None,
) -> TestResult:
    connected = is_connected_class(classification)
    selected = selected_for_output(ctx.cfg.mode, classification)
    return TestResult(
        index=ctx.index,
        total=ctx.total,
        proxy=ctx.proxy,
        proxy_id=ctx.proxy_id,
        mode=ctx.cfg.mode,
        proxy_type=ctx.proxy_type,
        classification=classification,
        selected=selected,
        connected=connected,
        stage=stage,
        failure_category=""
        if category == FailureCategory.UNKNOWN_ERROR and not reason
        else category.value,
        failure_reason=reason,
        local_port=ctx.local_port,
        dns=ctx.dns,
        endpoint_used=http.endpoint_used if http else "",
        http=http,
        stage2=stage2,
        log_file=ctx.per_proxy_log_file,
        latencies=ctx.latencies,
    )


async def test_proxy_once(
    ctx: ProxyTestContext,
    port_allocator: PortAllocator,
    logger: logging.Logger,
) -> TestResult:
    started_total = now_perf()
    cfg = ctx.cfg
    log_buffer = ClientLogBuffer()

    try:
        # PARSE
        ctx.set_stage(Stage.PARSE)
        try:
            ctx.parsed = parse_proxy_url(ctx.proxy)
            ctx.proxy_type = str(ctx.parsed["type"])
        except ProxyParseError as exc:
            ctx.latencies.total_time_ms = ms_since(started_total)
            return make_result(
                ctx,
                classification=Classification.PARSE_FAILED,
                stage=Stage.PARSE,
                category=FailureCategory.PARSE_ERROR,
                reason=str(exc),
            )

        if cfg.per_proxy_logs:
            cfg.proxy_log_dir.mkdir(parents=True, exist_ok=True)
            ctx.per_proxy_log_file = str(
                cfg.proxy_log_dir
                / f"{ctx.index:06d}_{ctx.proxy_type}_{ctx.proxy_id}.log"
            )

        # Optional local DNS diagnostics. DNS failure is recorded but not fatal.
        if MODE_DEFAULTS[cfg.mode].run_local_dns:
            ctx.set_stage(Stage.DNS_RESOLUTION)
            ctx.dns = await resolve_host(
                str(ctx.parsed["host"]), int(ctx.parsed["port"])
            )
            ctx.latencies.dns_time_ms = ctx.dns.dns_time_ms
            if ctx.dns.error:
                logger.info(
                    "[%s] local DNS failed host=%s error=%s",
                    ctx.proxy_id,
                    ctx.dns.host,
                    ctx.dns.error,
                )
            else:
                logger.debug(
                    "[%s] local DNS host=%s ips=%s",
                    ctx.proxy_id,
                    ctx.dns.host,
                    ctx.dns.resolved_ips,
                )

        # BUILD_CONFIG
        ctx.set_stage(Stage.BUILD_CONFIG)
        ctx.local_port = await port_allocator.acquire()
        try:
            client_cmd, ctx.config_file = build_client(ctx.parsed, ctx.local_port, cfg)
        except Exception as exc:
            ctx.latencies.total_time_ms = ms_since(started_total)
            return make_result(
                ctx,
                classification=Classification.DEAD,
                stage=Stage.BUILD_CONFIG,
                category=FailureCategory.BUILD_ERROR,
                reason=f"build_failed: {type(exc).__name__}: {exc}",
            )

        # CLIENT_START
        ctx.set_stage(Stage.CLIENT_START)
        startup_start = now_perf()
        try:
            ctx.process = await launch_client(client_cmd, ctx, logger)
        except FileNotFoundError:
            ctx.latencies.startup_time_ms = ms_since(startup_start)
            ctx.latencies.total_time_ms = ms_since(started_total)
            binary = client_cmd[0] if client_cmd else "client"
            return make_result(
                ctx,
                classification=Classification.DEAD,
                stage=Stage.CLIENT_START,
                category=FailureCategory.CLIENT_START_ERROR,
                reason=f"binary not found: {binary}",
            )
        except Exception as exc:
            ctx.latencies.startup_time_ms = ms_since(startup_start)
            ctx.latencies.total_time_ms = ms_since(started_total)
            return make_result(
                ctx,
                classification=Classification.DEAD,
                stage=Stage.CLIENT_START,
                category=FailureCategory.CLIENT_START_ERROR,
                reason=f"failed to start client: {type(exc).__name__}: {exc}",
            )

        ctx.capture_task = asyncio.create_task(
            capture_process_output(ctx.process, log_buffer, ctx.per_proxy_log_file)
        )
        ctx.latencies.startup_time_ms = ms_since(startup_start)

        # WAIT_FOR_LOCAL_SOCKS
        ctx.set_stage(Stage.WAIT_FOR_LOCAL_SOCKS)
        socks_result = await wait_for_local_socks_ready(
            ctx.process, LOCAL_HOST, ctx.local_port, cfg.startup_timeout
        )
        ctx.latencies.socks_ready_time_ms = socks_result.elapsed_ms
        if not socks_result.ready:
            await finish_capture_task(ctx.capture_task)
            category, reason = enhance_failure_from_client_log(
                log_buffer.text(), socks_result.category, socks_result.reason
            )
            classification = (
                Classification.UNKNOWN
                if category == FailureCategory.TIMEOUT_ERROR
                else Classification.DEAD
            )
            ctx.latencies.total_time_ms = ms_since(started_total)
            return make_result(
                ctx,
                classification=classification,
                stage=socks_result.stage,
                category=category,
                reason=reason,
            )

        # HTTP_TEST
        ctx.set_stage(Stage.HTTP_TEST)
        http = await run_http_tests_through_socks(
            ctx.local_port,
            cfg,
            test_all=MODE_DEFAULTS[cfg.mode].test_all_endpoints,
            logger=logger,
        )
        ctx.latencies.http_time_ms = http.elapsed_ms

        if not http.success:
            await finish_capture_task(ctx.capture_task)
            category, reason = enhance_failure_from_client_log(
                log_buffer.text(), http.category, http.reason
            )
            # If SOCKS opened but all HTTP tests fail, classify UNKNOWN by default; it may be endpoint/network instability.
            classification = Classification.UNKNOWN
            ctx.latencies.total_time_ms = ms_since(started_total)
            return make_result(
                ctx,
                classification=classification,
                stage=http.stage,
                category=category,
                reason=reason,
                http=http,
            )

        # Optional strict Stage2 checks
        if MODE_DEFAULTS[cfg.mode].run_stage2:
            ctx.set_stage(Stage.STAGE2_DNS_OVER_PROXY)
            stage2 = await run_stage2_checks(ctx.local_port)
            ctx.latencies.stage2_time_ms = stage2.elapsed_ms
            classification, category, reason, stage = classify_after_stage2(
                ctx, http, stage2
            )
            ctx.latencies.total_time_ms = ms_since(started_total)
            return make_result(
                ctx,
                classification=classification,
                stage=stage,
                category=category,
                reason=reason,
                http=http,
                stage2=stage2,
            )

        classification, category, reason, stage = classify_after_http(ctx, http)
        ctx.latencies.total_time_ms = ms_since(started_total)
        return make_result(
            ctx,
            classification=classification,
            stage=stage,
            category=category,
            reason=reason,
            http=http,
        )

    except asyncio.CancelledError:
        raise
    except Exception as exc:
        ctx.latencies.total_time_ms = ms_since(started_total)
        return make_result(
            ctx,
            classification=Classification.UNKNOWN,
            stage=ctx.current_stage,
            category=FailureCategory.UNKNOWN_ERROR,
            reason=f"unexpected_error: {type(exc).__name__}: {exc}",
        )
    finally:
        await terminate_process(ctx.process)
        await finish_capture_task(ctx.capture_task)
        if ctx.config_file:
            with suppress(Exception):
                os.unlink(ctx.config_file)
        await port_allocator.release(ctx.local_port)


async def test_proxy_with_timeout(
    index: int,
    total: int,
    proxy: str,
    cfg: AppConfig,
    port_allocator: PortAllocator,
    logger: logging.Logger,
) -> TestResult:
    started = now_perf()
    ctx = ProxyTestContext(
        index=index, total=total, proxy=proxy, proxy_id=short_proxy_id(proxy), cfg=cfg
    )
    task = asyncio.create_task(test_proxy_once(ctx, port_allocator, logger))
    try:
        return await asyncio.wait_for(task, timeout=cfg.per_proxy_timeout)
    except asyncio.TimeoutError:
        # Cancellation enters test_proxy_once's finally block, so child processes and
        # temp config files should still be cleaned up. Because ctx is shared, the
        # timeout report can name the actual active stage instead of only PER_PROXY.
        task.cancel()
        with suppress(BaseException):
            await task
        return TestResult(
            index=index,
            total=total,
            proxy=proxy,
            proxy_id=ctx.proxy_id,
            mode=cfg.mode,
            proxy_type=ctx.proxy_type,
            classification=Classification.UNKNOWN,
            selected=False,
            connected=False,
            stage=ctx.current_stage,
            failure_category=FailureCategory.TIMEOUT_ERROR.value,
            failure_reason=f"timeout_stage={ctx.current_stage.value} elapsed={cfg.per_proxy_timeout:.2f}s",
            local_port=ctx.local_port,
            dns=ctx.dns,
            log_file=ctx.per_proxy_log_file,
            latencies=Latencies(total_time_ms=ms_since(started)),
        )


async def worker(
    index: int,
    total: int,
    proxy: str,
    semaphore: asyncio.Semaphore,
    cfg: AppConfig,
    port_allocator: PortAllocator,
    logger: logging.Logger,
    stats: ProgressStats,
    stats_lock: asyncio.Lock,
) -> TestResult:
    async with semaphore:
        async with stats_lock:
            stats.active += 1
        try:
            return await test_proxy_with_timeout(
                index, total, proxy, cfg, port_allocator, logger
            )
        finally:
            async with stats_lock:
                stats.active -= 1


async def run_all(
    proxy_list: list[str],
    cfg: AppConfig,
    logger: logging.Logger,
    reporter: ConsoleReporter,
) -> tuple[list[TestResult], ProgressStats]:
    semaphore = asyncio.Semaphore(cfg.threads)
    port_allocator = PortAllocator()
    output = OutputManager(cfg)
    stats = ProgressStats(total=len(proxy_list))
    stats_lock = asyncio.Lock()
    stop_event = asyncio.Event()
    last_result_box: dict[str, Optional[TestResult]] = {"last": None}

    def get_last_result() -> Optional[TestResult]:
        return last_result_box["last"]

    progress_task = asyncio.create_task(
        progress_reporter(
            stats,
            stats_lock,
            stop_event,
            reporter,
            cfg.progress_interval,
            get_last_result,
        )
    )

    tasks = [
        asyncio.create_task(
            worker(
                i + 1,
                len(proxy_list),
                proxy,
                semaphore,
                cfg,
                port_allocator,
                logger,
                stats,
                stats_lock,
            )
        )
        for i, proxy in enumerate(proxy_list)
    ]

    results: list[TestResult] = []
    try:
        for fut in asyncio.as_completed(tasks):
            result = await fut
            results.append(result)
            last_result_box["last"] = result
            await output.write_result(result)

            async with stats_lock:
                stats.done += 1
                stats.total_latency_ms += result.latencies.total_time_ms or 0.0
                stats.class_counts[result.classification] += 1
                if result.selected:
                    stats.selected += 1
                if result.connected:
                    stats.connected += 1
                if result.classification == Classification.UNKNOWN:
                    stats.unknown += 1
                if result.classification in {
                    Classification.DEAD,
                    Classification.PARSE_FAILED,
                }:
                    stats.failed += 1
                if result.failure_category:
                    stats.category_counts[result.failure_category] += 1
                if result.failure_reason:
                    stats.reason_counts[result.failure_reason[:500]] += 1

                should_progress = (
                    stats.done % cfg.progress_every == 0 or stats.done == stats.total
                )

            logger.info(
                "result index=%s/%s id=%s mode=%s class=%s selected=%s connected=%s stage=%s category=%s reason=%s total_ms=%s endpoint=%s log_file=%s",
                result.index,
                result.total,
                result.proxy_id,
                result.mode.value,
                result.classification.value,
                result.selected,
                result.connected,
                result.stage.value,
                result.failure_category,
                result.failure_reason,
                fmt_ms(result.latencies.total_time_ms),
                result.endpoint_used,
                result.log_file,
            )
            reporter.result_line(result)
            if should_progress:
                async with stats_lock:
                    reporter.progress(stats, result, force=True)
    finally:
        stop_event.set()
        with suppress(Exception):
            await progress_task
        output.close()
    return results, stats


# ---------- sort-by-ping and ping-only scan ----------


def result_ping_ms(result: TestResult) -> Optional[float]:
    """Best latency value for sorting full proxy-test results."""
    if result.stage2 and result.stage2.avg_latency_ms is not None:
        return result.stage2.avg_latency_ms
    if result.latencies.http_time_ms is not None:
        return result.latencies.http_time_ms
    if result.latencies.total_time_ms is not None:
        return result.latencies.total_time_ms
    return None


def write_sorted_selected_output(
    cfg: AppConfig, results: list[TestResult]
) -> dict[str, Any]:
    """Write selected configs ordered by measured proxy latency."""
    selected = [r for r in results if r.selected]
    sorted_selected = sorted(
        selected,
        key=lambda r: (
            result_ping_ms(r) is None,
            result_ping_ms(r) if result_ping_ms(r) is not None else float("inf"),
            r.index,
        ),
    )
    cfg.output.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if cfg.append else "w"
    with open(cfg.output, mode, encoding="utf-8", errors="replace", newline="\n") as f:
        for result in sorted_selected:
            f.write(result.proxy + "\n")

    latencies = [
        result_ping_ms(r) for r in sorted_selected if result_ping_ms(r) is not None
    ]
    return {
        "enabled": True,
        "output": str(cfg.output),
        "selected_written": len(sorted_selected),
        "fastest_ms": min(latencies) if latencies else None,
        "slowest_ms": max(latencies) if latencies else None,
    }


@dataclass
class PingOnlyResult:
    index: int
    total: int
    proxy: str
    proxy_id: str
    proxy_type: str = ""
    host: str = ""
    port: Optional[int] = None
    success: bool = False
    timed_out: bool = False
    latency_ms: Optional[float] = None
    reason: str = ""

    def to_json_dict(self) -> dict[str, Any]:
        return asdict(self)


def ping_sort_key(result: PingOnlyResult) -> tuple[int, float, int]:
    # Reachable configs first by latency. Non-timeout failures next. Timeouts last,
    # so the reported timeout cliff is contiguous in the sorted output.
    if result.success and result.latency_ms is not None:
        return (0, result.latency_ms, result.index)
    if result.timed_out:
        return (2, float("inf"), result.index)
    return (1, float("inf"), result.index)


async def tcp_ping_config(
    index: int, total: int, proxy: str, cfg: AppConfig
) -> PingOnlyResult:
    started = now_perf()
    result = PingOnlyResult(
        index=index, total=total, proxy=proxy, proxy_id=short_proxy_id(proxy)
    )
    try:
        parsed = parse_proxy_url(proxy)
        result.proxy_type = str(parsed.get("type", ""))
        result.host = str(parsed["host"])
        result.port = int(parsed["port"])
    except Exception as exc:
        result.reason = f"parse_failed: {type(exc).__name__}: {exc}"
        return result

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(result.host, int(result.port)),
            timeout=cfg.ping_timeout,
        )
        writer.close()
        await writer.wait_closed()
        result.success = True
        result.latency_ms = ms_since(started)
        return result
    except asyncio.TimeoutError:
        result.timed_out = True
        result.latency_ms = ms_since(started)
        result.reason = f"timeout elapsed={cfg.ping_timeout:.2f}s"
        return result
    except Exception as exc:
        result.latency_ms = ms_since(started)
        result.reason = f"connect_failed: {type(exc).__name__}: {exc}"
        return result


async def run_ping_only(
    proxy_list: list[str],
    cfg: AppConfig,
    logger: logging.Logger,
    reporter: ConsoleReporter,
) -> list[PingOnlyResult]:
    semaphore = asyncio.Semaphore(cfg.threads)
    results: list[PingOnlyResult] = []
    done = 0
    total = len(proxy_list)

    async def one(index: int, proxy: str) -> PingOnlyResult:
        async with semaphore:
            return await tcp_ping_config(index, total, proxy, cfg)

    tasks = [
        asyncio.create_task(one(i + 1, proxy)) for i, proxy in enumerate(proxy_list)
    ]
    for fut in asyncio.as_completed(tasks):
        result = await fut
        results.append(result)
        done += 1
        if done % cfg.progress_every == 0 or done == total:
            ok = sum(1 for r in results if r.success)
            timed_out = sum(1 for r in results if r.timed_out)
            if not cfg.quiet:
                print(
                    f"PING PROGRESS {done}/{total} | reachable={ok} | timeout={timed_out}",
                    file=sys.stderr,
                    flush=True,
                )
        logger.info(
            "ping_result index=%s/%s id=%s success=%s timeout=%s latency_ms=%s reason=%s",
            result.index,
            result.total,
            result.proxy_id,
            result.success,
            result.timed_out,
            fmt_ms(result.latency_ms),
            result.reason,
        )
    return results


def write_ping_only_outputs(
    cfg: AppConfig, results: list[PingOnlyResult]
) -> dict[str, Any]:
    sorted_results = sorted(results, key=ping_sort_key)
    cfg.output.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if cfg.append else "w"
    with open(cfg.output, mode, encoding="utf-8", errors="replace", newline="\n") as f:
        for result in sorted_results:
            f.write(result.proxy + "\n")

    if cfg.jsonl_path:
        cfg.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        json_mode = "a" if cfg.append else "w"
        with open(
            cfg.jsonl_path, json_mode, encoding="utf-8", errors="replace", newline="\n"
        ) as f:
            for result in sorted_results:
                f.write(json.dumps(result.to_json_dict(), ensure_ascii=False) + "\n")

    if cfg.csv_path:
        cfg.csv_path.parent.mkdir(parents=True, exist_ok=True)
        csv_mode = "a" if cfg.append else "w"
        fieldnames = [
            "sorted_position",
            "index",
            "proxy_id",
            "proxy",
            "type",
            "host",
            "port",
            "success",
            "timed_out",
            "latency_ms",
            "reason",
        ]
        csv_exists = (
            cfg.append and cfg.csv_path.exists() and cfg.csv_path.stat().st_size > 0
        )
        with open(
            cfg.csv_path, csv_mode, encoding="utf-8", errors="replace", newline=""
        ) as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if not csv_exists:
                writer.writeheader()
            for pos, result in enumerate(sorted_results, start=1):
                writer.writerow(
                    {
                        "sorted_position": pos,
                        "index": result.index,
                        "proxy_id": result.proxy_id,
                        "proxy": result.proxy,
                        "type": result.proxy_type,
                        "host": result.host,
                        "port": result.port if result.port is not None else "",
                        "success": str(result.success),
                        "timed_out": str(result.timed_out),
                        "latency_ms": fmt_ms(result.latency_ms),
                        "reason": result.reason,
                    }
                )

    first_timeout_position = next(
        (i for i, r in enumerate(sorted_results, start=1) if r.timed_out), None
    )
    reachable_latencies = [
        r.latency_ms for r in sorted_results if r.success and r.latency_ms is not None
    ]
    return {
        "output": str(cfg.output),
        "total": len(sorted_results),
        "reachable": sum(1 for r in sorted_results if r.success),
        "timed_out": sum(1 for r in sorted_results if r.timed_out),
        "failed_without_timeout": sum(
            1 for r in sorted_results if not r.success and not r.timed_out
        ),
        "first_timeout_sorted_position": first_timeout_position,
        "fastest_ms": min(reachable_latencies) if reachable_latencies else None,
        "slowest_ms": max(reachable_latencies) if reachable_latencies else None,
    }


def build_ping_only_summary(
    results: list[PingOnlyResult],
    cfg: AppConfig,
    elapsed_seconds: float,
    output_info: dict[str, Any],
) -> dict[str, Any]:
    reason_counts = Counter(r.reason[:500] for r in results if r.reason)
    return {
        "mode": "ping-only",
        "sort_ping": True,
        "sort_ping_only": True,
        "total": len(results),
        "reachable": sum(1 for r in results if r.success),
        "timed_out": sum(1 for r in results if r.timed_out),
        "failed_without_timeout": sum(
            1 for r in results if not r.success and not r.timed_out
        ),
        "first_timeout_sorted_position": output_info.get(
            "first_timeout_sorted_position"
        ),
        "ping_timeout_seconds": cfg.ping_timeout,
        "elapsed_seconds": elapsed_seconds,
        "fastest_ms": output_info.get("fastest_ms"),
        "slowest_ms": output_info.get("slowest_ms"),
        "top_failure_reasons": dict(reason_counts.most_common(15)),
        "outputs": {
            "sorted_output": str(cfg.output),
            "summary": str(cfg.summary_path),
            "log_file": str(cfg.log_file) if cfg.log_file else None,
            **({"jsonl": str(cfg.jsonl_path)} if cfg.jsonl_path else {}),
            **({"csv": str(cfg.csv_path)} if cfg.csv_path else {}),
        },
    }


def ordinal(n: int) -> str:
    if 10 <= n % 100 <= 20:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


# ---------- summary ----------


def build_summary(
    results: list[TestResult],
    stats: ProgressStats,
    cfg: AppConfig,
    elapsed_seconds: float,
) -> dict[str, Any]:
    total = len(results)
    class_counts = Counter(r.classification.value for r in results)
    category_counts = Counter(r.failure_category for r in results if r.failure_category)
    reason_counts = Counter(r.failure_reason[:500] for r in results if r.failure_reason)
    connected = sum(1 for r in results if r.connected)
    selected = sum(1 for r in results if r.selected)
    failed = (
        class_counts[Classification.DEAD.value]
        + class_counts[Classification.PARSE_FAILED.value]
    )
    unknown = class_counts[Classification.UNKNOWN.value]
    avg_latency_ms = (
        sum((r.latencies.total_time_ms or 0.0) for r in results) / total
        if total
        else 0.0
    )

    outputs: dict[str, Any] = {
        "selected_output": str(cfg.output),
        "summary": str(cfg.summary_path),
        "log_file": str(cfg.log_file) if cfg.log_file else None,
    }
    if cfg.save_failed:
        outputs["failed"] = str(cfg.save_failed)
    if cfg.save_unknown:
        outputs["unknown"] = str(cfg.save_unknown)
    if cfg.jsonl_path:
        outputs["jsonl"] = str(cfg.jsonl_path)
    if cfg.csv_path:
        outputs["csv"] = str(cfg.csv_path)
    if cfg.save_buckets:
        outputs["buckets"] = [
            str(cfg.output.parent / f"{c.value.lower()}.txt") for c in Classification
        ]
    if cfg.per_proxy_logs:
        outputs["proxy_log_dir"] = str(cfg.proxy_log_dir)

    return {
        "mode": "ping-only" if cfg.sort_ping_only else cfg.mode.value,
        "sort_ping": cfg.sort_ping,
        "sort_ping_only": cfg.sort_ping_only,
        "total": total,
        "tested": total,
        "selected": selected,
        "connected": connected,
        "failed": failed,
        "unknown": unknown,
        "good": class_counts[Classification.GOOD.value],
        "slow": class_counts[Classification.SLOW_BUT_WORKING.value],
        "partial": class_counts[Classification.PARTIAL.value],
        "unstable": class_counts[Classification.UNSTABLE.value],
        "parse_failed": class_counts[Classification.PARSE_FAILED.value],
        "connected_rate": (connected / total * 100.0) if total else 0.0,
        "selected_rate": (selected / total * 100.0) if total else 0.0,
        "average_latency_ms": avg_latency_ms,
        "elapsed_seconds": elapsed_seconds,
        "top_failure_categories": dict(category_counts.most_common(15)),
        "top_failure_reasons": dict(reason_counts.most_common(15)),
        "outputs": outputs,
    }


def write_summary(path: Path, summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", errors="replace", newline="\n") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
        f.write("\n")


# ---------- CLI ----------


def read_proxy_lines(path: Optional[Path]) -> list[str]:
    if path:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return [
                line
                for line in (normalize_input_line(line) for line in f)
                if line and not line.startswith("#")
            ]
    print("Enter proxy URLs (one per line, Ctrl+D to finish):", file=sys.stderr)
    return [
        line
        for line in (normalize_input_line(line) for line in sys.stdin)
        if line and not line.startswith("#")
    ]


def parse_args(argv: Optional[Iterable[str]] = None) -> AppConfig:
    parser = argparse.ArgumentParser(
        description="Merged VLESS/VMess/Trojan/Shadowsocks proxy probe with fast, balanced, strict, and diagnose modes.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-f", "--file", type=Path, help="File containing proxy URLs, one per line."
    )
    parser.add_argument(
        "--mode",
        choices=[m.value for m in Mode],
        default=None,
        help="Testing profile. If omitted with --sort-ping, only server TCP pings are checked.",
    )
    parser.add_argument(
        "--threads", type=int, help="Concurrent proxy tests. Defaults depend on --mode."
    )
    parser.add_argument(
        "--startup-timeout",
        type=float,
        help="Seconds to wait for local SOCKS readiness. Defaults depend on --mode.",
    )
    parser.add_argument(
        "--test-timeout",
        type=float,
        help="HTTP request timeout in seconds. Defaults depend on --mode.",
    )
    parser.add_argument(
        "--per-proxy-timeout",
        type=float,
        help="Overall timeout per proxy in seconds. Defaults depend on --mode.",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path("connected.txt"),
        help="Selected configs output file.",
    )
    parser.add_argument(
        "--summary",
        dest="summary_path",
        type=Path,
        default=Path("summary.json"),
        help="Summary JSON output.",
    )
    parser.add_argument(
        "--log-file", type=Path, default=Path("proxy_probe.log"), help="Run log file."
    )
    parser.add_argument(
        "--no-log-file", action="store_true", help="Disable run log file."
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="No console progress/output except fatal startup errors.",
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable colored console output."
    )

    parser.add_argument(
        "--save-failed", type=Path, help="Save definitely failed configs here."
    )
    parser.add_argument(
        "--save-unknown",
        type=Path,
        help="Save inconclusive timeout/unstable configs here.",
    )
    parser.add_argument(
        "--save-buckets",
        action="store_true",
        help="Create good/slow/partial/unstable/dead/unknown/parse_failed bucket files.",
    )
    parser.add_argument(
        "--jsonl", dest="jsonl_path", type=Path, help="Detailed JSONL result file."
    )
    parser.add_argument(
        "--csv", dest="csv_path", type=Path, help="Detailed CSV result file."
    )
    parser.add_argument(
        "--per-proxy-logs",
        action="store_true",
        help="Create proxy_logs/ with Xray/ss-local output per config.",
    )
    parser.add_argument(
        "--proxy-log-dir",
        type=Path,
        default=Path("proxy_logs"),
        help="Directory for --per-proxy-logs.",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug run logs and Xray debug loglevel.",
    )
    parser.add_argument(
        "--progress-interval",
        type=float,
        default=DEFAULT_PROGRESS_INTERVAL,
        help="Seconds between progress summaries.",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=DEFAULT_PROGRESS_EVERY,
        help="Also print a loud progress summary every N completed configs.",
    )
    parser.add_argument("--xray-bin", default="xray", help="Xray executable path/name.")
    parser.add_argument(
        "--ss-bin",
        default="ss-local",
        help="Shadowsocks local client executable path/name.",
    )
    parser.add_argument(
        "--fsync-output",
        action="store_true",
        help="fsync after each output write; safer but slower.",
    )
    parser.add_argument(
        "--append",
        action="store_true",
        help="Append to output files instead of overwriting them.",
    )
    parser.add_argument(
        "--sort-ping",
        action="store_true",
        help="Write selected configs sorted by measured ping. If --mode is omitted, run a ping-only TCP reachability scan instead of a full proxy test.",
    )
    parser.add_argument(
        "--ping-timeout",
        type=float,
        default=5.0,
        help="Seconds to wait for each TCP ping in --sort-ping ping-only mode.",
    )
    parser.add_argument(
        "--slow-threshold-ms",
        type=float,
        default=DEFAULT_SLOW_THRESHOLD_MS,
        help="Latency above this is SLOW_BUT_WORKING.",
    )
    parser.add_argument(
        "--test-url",
        dest="test_urls",
        action="append",
        help="Override/add HTTP validation URL. Can be repeated.",
    )

    ns = parser.parse_args(argv)
    mode_was_provided = ns.mode is not None
    mode = Mode(ns.mode) if mode_was_provided else Mode.FAST
    defaults = MODE_DEFAULTS[mode]

    threads = ns.threads if ns.threads is not None else defaults.threads
    startup_timeout = (
        ns.startup_timeout
        if ns.startup_timeout is not None
        else defaults.startup_timeout
    )
    test_timeout = (
        ns.test_timeout if ns.test_timeout is not None else defaults.test_timeout
    )
    per_proxy_timeout = (
        ns.per_proxy_timeout
        if ns.per_proxy_timeout is not None
        else defaults.per_proxy_timeout
    )

    if threads <= 0:
        parser.error("--threads must be > 0")
    if startup_timeout <= 0 or test_timeout <= 0 or per_proxy_timeout <= 0:
        parser.error("timeouts must be > 0")
    if ns.progress_every <= 0:
        parser.error("--progress-every must be > 0")
    if ns.slow_threshold_ms <= 0:
        parser.error("--slow-threshold-ms must be > 0")
    if ns.ping_timeout <= 0:
        parser.error("--ping-timeout must be > 0")

    sort_ping_only = bool(ns.sort_ping and not mode_was_provided)

    return AppConfig(
        input_file=ns.file,
        mode=mode,
        threads=threads,
        startup_timeout=startup_timeout,
        test_timeout=test_timeout,
        per_proxy_timeout=per_proxy_timeout,
        output=ns.output,
        summary_path=ns.summary_path,
        log_file=None if ns.no_log_file else ns.log_file,
        quiet=ns.quiet,
        no_color=ns.no_color,
        debug=ns.debug,
        progress_interval=ns.progress_interval,
        progress_every=ns.progress_every,
        xray_bin=ns.xray_bin,
        ss_bin=ns.ss_bin,
        fsync_output=ns.fsync_output,
        save_failed=ns.save_failed,
        save_unknown=ns.save_unknown,
        save_buckets=ns.save_buckets,
        jsonl_path=ns.jsonl_path,
        csv_path=ns.csv_path,
        per_proxy_logs=ns.per_proxy_logs,
        proxy_log_dir=ns.proxy_log_dir,
        test_urls=ns.test_urls or BASIC_TEST_URLS,
        slow_threshold_ms=ns.slow_threshold_ms,
        append=ns.append,
        sort_ping=ns.sort_ping,
        sort_ping_only=sort_ping_only,
        ping_timeout=ns.ping_timeout,
    )


def main(argv: Optional[Iterable[str]] = None) -> int:
    configure_utf8_stdio()
    cfg = parse_args(argv)
    logger = setup_file_logger(cfg)
    reporter = ConsoleReporter(cfg)

    if IMPORT_ERROR is not None and not cfg.sort_ping_only:
        print(f"Missing required Python dependency: {IMPORT_ERROR}", file=sys.stderr)
        print(
            "Install dependencies: pip install aiohttp aiohttp-socks", file=sys.stderr
        )
        return 2

    try:
        proxy_urls = read_proxy_lines(cfg.input_file)
    except FileNotFoundError:
        print(f"Input file not found: {cfg.input_file}", file=sys.stderr)
        return 2

    if not proxy_urls:
        print("No proxy URLs provided.", file=sys.stderr)
        return 1

    logger.info(
        "START mode=%s total=%s threads=%s startup_timeout=%.1fs test_timeout=%.1fs per_proxy_timeout=%.1fs output=%s summary=%s log_file=%s quiet=%s debug=%s sort_ping=%s sort_ping_only=%s",
        "ping-only" if cfg.sort_ping_only else cfg.mode.value,
        len(proxy_urls),
        cfg.threads,
        cfg.startup_timeout,
        cfg.test_timeout,
        cfg.per_proxy_timeout,
        cfg.output,
        cfg.summary_path,
        cfg.log_file,
        cfg.quiet,
        cfg.debug,
        cfg.sort_ping,
        cfg.sort_ping_only,
    )
    reporter.start(len(proxy_urls))

    if cfg.sort_ping_only:
        started_ping = now_perf()
        try:
            ping_results = asyncio.run(run_ping_only(proxy_urls, cfg, logger, reporter))
        except KeyboardInterrupt:
            logger.warning("Interrupted by user during ping-only scan")
            return 130
        except Exception as exc:
            logger.exception("Fatal error: %s", exc)
            print(f"Fatal error: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 2

        elapsed_ping = time.perf_counter() - started_ping
        output_info = write_ping_only_outputs(cfg, ping_results)
        summary = build_ping_only_summary(ping_results, cfg, elapsed_ping, output_info)
        write_summary(cfg.summary_path, summary)
        logger.info("SUMMARY %s", json.dumps(summary, ensure_ascii=False))

        if not cfg.quiet:
            print(f"output file sorted {cfg.output}", file=sys.stderr, flush=True)
            first_timeout = output_info.get("first_timeout_sorted_position")
            if first_timeout is None:
                print(
                    "no timeout cliff found in the sorted configurations",
                    file=sys.stderr,
                    flush=True,
                )
            else:
                print(
                    f"from {ordinal(int(first_timeout))} configuration, configs connections dies because of timeout :(",
                    file=sys.stderr,
                    flush=True,
                )
        return 0

    started = now_perf()
    results: list[TestResult] = []
    stats = ProgressStats(total=len(proxy_urls))
    try:
        results, stats = asyncio.run(run_all(proxy_urls, cfg, logger, reporter))
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        # Best-effort summary for whatever has completed.
        elapsed = time.perf_counter() - started
        summary = build_summary(results, stats, cfg, elapsed)
        summary["interrupted"] = True
        write_summary(cfg.summary_path, summary)
        return 130
    except Exception as exc:
        logger.exception("Fatal error: %s", exc)
        print(f"Fatal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    elapsed = time.perf_counter() - started
    summary = build_summary(results, stats, cfg, elapsed)
    if cfg.sort_ping:
        summary["sort_ping_output"] = write_sorted_selected_output(cfg, results)
        if not cfg.quiet:
            print(f"output file sorted {cfg.output}", file=sys.stderr, flush=True)
    write_summary(cfg.summary_path, summary)
    logger.info("SUMMARY %s", json.dumps(summary, ensure_ascii=False))
    reporter.final(summary)

    # For web-server style automation, exit 0 when the run completed, even if zero configs connect.
    # The caller should inspect summary.json for selected/connected counts.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
