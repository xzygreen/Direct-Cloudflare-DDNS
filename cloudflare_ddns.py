#!/usr/bin/env python3
"""Small, dependency-free Cloudflare dynamic DNS client.

Public IP lookups can use a proxy-free urllib opener, while Cloudflare API
traffic can independently keep using the host's normal network settings.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import stat
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

try:
    import fcntl
except ImportError:  # Windows
    fcntl = None  # type: ignore[assignment]
try:
    import msvcrt
except ImportError:  # POSIX
    msvcrt = None  # type: ignore[assignment]

if sys.version_info < (3, 9):
    sys.stderr.write("cloudflare_ddns 需要 Python 3.9 或更高版本\n")
    sys.exit(2)


try:
    VERSION = Path(__file__).with_name("VERSION").read_text(encoding="utf-8").strip()
except OSError:
    VERSION = "2.0.0"
API_BASE = "https://api.cloudflare.com/client/v4"
DEFAULT_IP_SERVICES = {
    "ipv4": [
        "https://api4.ipify.org",
        "https://ipv4.icanhazip.com",
        "https://v4.ident.me",
    ],
    "ipv6": [
        "https://api6.ipify.org",
        "https://ipv6.icanhazip.com",
        "https://v6.ident.me",
    ],
}
USER_AGENT = f"direct-cloudflare-ddns/{VERSION}"
RETRYABLE_HTTP_STATUS = frozenset({408, 429, 500, 502, 503, 504})
RETRY_BACKOFF_SECONDS = (1.0, 2.0, 4.0)
# 服务端 Retry-After 超过该秒数时放弃本轮重试，交给下一个同步周期。
RETRY_AFTER_LIMIT = 30.0
# 同一地址族连续检测失败达到该次数后，提示 Cloudflare 记录可能已经失效。
STALE_RECORD_WARNING_THRESHOLD = 3
CONFIG_SCHEMA_VERSION = 2
MAX_IP_SERVICES_PER_FAMILY = 10
MAX_CLOUDFLARE_RESPONSE_BYTES = 4 * 1024 * 1024
LOG = logging.getLogger("cloudflare-ddns")
JSON_EVENTS_ENABLED = False
_EVENT_LOCK = threading.Lock()


def _emit_event(kind: str, **payload: Any) -> None:
    if not JSON_EVENTS_ENABLED:
        return
    document = {"event": kind, "timestamp": int(time.time()), **payload}
    with _EVENT_LOCK:
        print("@@DDNS_EVENT@@" + json.dumps(document, ensure_ascii=False, sort_keys=True), flush=True)


class ConfigError(ValueError):
    """Raised when configuration is missing or unsafe."""


class DetectionError(RuntimeError):
    """Raised when a trustworthy public IP cannot be detected."""


class CloudflareError(RuntimeError):
    """Raised for Cloudflare HTTP or API errors."""

    def __init__(
        self,
        message: str,
        *,
        status: Optional[int] = None,
        retryable: bool = False,
        retry_after: Optional[float] = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.retryable = retryable
        self.retry_after = retry_after


def _direct_opener() -> urllib.request.OpenerDirector:
    """Return an opener which ignores env and OS HTTP proxy settings."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _system_opener() -> urllib.request.OpenerDirector:
    """Return an opener which follows urllib's normal proxy behavior."""
    return urllib.request.build_opener()


def _make_opener(bypass_proxy: bool) -> urllib.request.OpenerDirector:
    return _direct_opener() if bypass_proxy else _system_opener()


# Python 的 idna 编解码对纯 ASCII 标签直接放行，空格、非法连字符等问题
# 会拖到 Cloudflare API 才报错，因此这里再做一次本地标签校验。
_LABEL_PATTERN = re.compile(r"[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?")


def _ascii_domain(name: str) -> str:
    name = name.strip().rstrip(".").lower()
    if not name:
        raise ConfigError("域名不能为空")
    labels = name.split(".")
    try:
        encoded = [label if label == "*" else label.encode("idna").decode("ascii") for label in labels]
    except UnicodeError as exc:
        raise ConfigError(f"无效域名 {name!r}: {exc}") from exc
    result = ".".join(encoded)
    if len(result) > 253 or any(not label or len(label) > 63 for label in encoded):
        raise ConfigError(f"无效域名: {name!r}")
    if "*" in encoded[1:]:
        raise ConfigError(f"无效域名 {name!r}：通配符 * 只能作为最左侧标签")
    if any(label != "*" and not _LABEL_PATTERN.fullmatch(label) for label in encoded):
        raise ConfigError(
            f"无效域名 {name!r}：标签只能包含字母、数字、下划线和连字符，且不能以连字符开头或结尾"
        )
    return result


def _require_bool(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{path} 必须是 true 或 false")
    return value


def _require_int(value: Any, path: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{path} 必须是整数")
    if not minimum <= value <= maximum:
        raise ConfigError(f"{path} 必须在 {minimum} 到 {maximum} 之间")
    return value


def _validate_urls(urls: Any, path: str, *, allow_insecure_http: bool) -> List[str]:
    if not isinstance(urls, list) or not urls:
        raise ConfigError(f"{path} 必须是非空 URL 列表")
    if len(urls) > MAX_IP_SERVICES_PER_FAMILY:
        raise ConfigError(f"{path} 最多允许 {MAX_IP_SERVICES_PER_FAMILY} 个查询服务")
    result: List[str] = []
    seen: set[str] = set()
    for index, value in enumerate(urls):
        if not isinstance(value, str):
            raise ConfigError(f"{path}[{index}] 必须是 URL 字符串")
        value = value.strip()
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ConfigError(f"{path}[{index}] 不是有效的 HTTP(S) URL")
        if parsed.username or parsed.password:
            raise ConfigError(f"{path}[{index}] 不允许在 URL 中包含凭据")
        if parsed.fragment:
            raise ConfigError(f"{path}[{index}] 不允许包含 URL 片段")
        duplicate_key = value.casefold()
        if duplicate_key in seen:
            raise ConfigError(f"{path} 包含重复查询服务：{value}")
        seen.add(duplicate_key)
        if parsed.scheme == "http":
            if not allow_insecure_http:
                raise ConfigError(
                    f"{path}[{index}] 使用不安全的 HTTP；请改用 HTTPS，"
                    "或显式设置 ip_detection.allow_insecure_http=true"
                )
            LOG.warning("%s[%d] 使用明文 HTTP，公网 IP 结果可能被篡改：%s", path, index, value)
        result.append(value)
    return result


def _agreement_by_family(value: Any) -> Dict[str, int]:
    """Normalize the v1 scalar and v2 per-family consensus formats."""
    if isinstance(value, int) and not isinstance(value, bool):
        agreement = _require_int(value, "ip_detection.minimum_agreement", 1, 10)
        return {"ipv4": agreement, "ipv6": agreement}
    if not isinstance(value, dict):
        raise ConfigError(
            "ip_detection.minimum_agreement 必须是整数，或包含 ipv4/ipv6 的对象"
        )
    _warn_unknown_keys(value, ("ipv4", "ipv6"), "ip_detection.minimum_agreement")
    return {
        "ipv4": _require_int(
            value.get("ipv4", 2), "ip_detection.minimum_agreement.ipv4", 1, 10
        ),
        "ipv6": _require_int(
            value.get("ipv6", 2), "ip_detection.minimum_agreement.ipv6", 1, 10
        ),
    }


def _warn_unknown_keys(mapping: Mapping[str, Any], allowed: Iterable[str], path: str) -> None:
    """Warn about misspelled keys instead of silently falling back to defaults."""
    unknown = sorted(set(mapping) - set(allowed))
    if unknown:
        LOG.warning("%s 包含未知配置项：%s；这些字段会被忽略，请检查拼写", path, ", ".join(unknown))


def load_config(path: Path) -> Dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except FileNotFoundError as exc:
        raise ConfigError(f"配置文件不存在: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"配置文件 JSON 格式错误（第 {exc.lineno} 行）: {exc.msg}") from exc
    except OSError as exc:
        raise ConfigError(f"无法读取配置文件 {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError("配置文件顶层必须是 JSON 对象")
    _warn_unknown_keys(
        raw,
        (
            "schema_version",
            "interval_seconds",
            "request_timeout_seconds",
            "cloudflare",
            "ip_detection",
            "records",
            # 由原生 App 使用；CLI 保留但不解析，避免破坏同一配置文件。
            "notifications",
        ),
        "配置文件顶层",
    )
    schema_version = raw.get("schema_version", 1)
    if isinstance(schema_version, bool) or not isinstance(schema_version, int):
        raise ConfigError("schema_version 必须是整数")
    if schema_version > CONFIG_SCHEMA_VERSION:
        raise ConfigError(
            f"配置版本 {schema_version} 高于程序支持的版本 {CONFIG_SCHEMA_VERSION}，请升级程序"
        )

    cloudflare = raw.get("cloudflare")
    if not isinstance(cloudflare, dict):
        raise ConfigError("缺少 cloudflare 配置对象")
    _warn_unknown_keys(
        cloudflare,
        ("api_token_env", "api_token_file", "zone_id", "zone_name", "bypass_proxy", "create_missing_records"),
        "cloudflare",
    )

    token_env = cloudflare.get("api_token_env", "CLOUDFLARE_API_TOKEN")
    token_file = cloudflare.get("api_token_file")
    if not isinstance(token_env, str) or not token_env:
        raise ConfigError("cloudflare.api_token_env 必须是非空字符串")
    if token_file is not None and (not isinstance(token_file, str) or not token_file):
        raise ConfigError("cloudflare.api_token_file 必须是非空字符串")
    if token_file:
        token_path = Path(token_file).expanduser()
        if not token_path.is_absolute():
            token_path = path.parent / token_path
        token_file = str(token_path)

    zone_id = cloudflare.get("zone_id")
    zone_name = cloudflare.get("zone_name")
    if zone_id is not None and (not isinstance(zone_id, str) or not zone_id.strip()):
        raise ConfigError("cloudflare.zone_id 必须是非空字符串")
    if zone_name is not None:
        if not isinstance(zone_name, str):
            raise ConfigError("cloudflare.zone_name 必须是字符串")
        zone_name = _ascii_domain(zone_name)
    if not zone_id and not zone_name:
        raise ConfigError("cloudflare.zone_id 与 cloudflare.zone_name 至少配置一个")

    interval = _require_int(raw.get("interval_seconds", 300), "interval_seconds", 30, 86400)
    timeout = _require_int(raw.get("request_timeout_seconds", 8), "request_timeout_seconds", 1, 60)

    detection_raw = raw.get("ip_detection", {})
    if not isinstance(detection_raw, dict):
        raise ConfigError("ip_detection 必须是 JSON 对象")
    _warn_unknown_keys(
        detection_raw,
        (
            "bypass_proxy",
            "allow_insecure_http",
            "source_diagnostics",
            "minimum_agreement",
            "services",
        ),
        "ip_detection",
    )
    bypass_detection = _require_bool(
        detection_raw.get("bypass_proxy", True), "ip_detection.bypass_proxy"
    )
    allow_insecure_http = _require_bool(
        detection_raw.get("allow_insecure_http", False),
        "ip_detection.allow_insecure_http",
    )
    source_diagnostics = _require_bool(
        detection_raw.get("source_diagnostics", False),
        "ip_detection.source_diagnostics",
    )
    consensus = _agreement_by_family(detection_raw.get("minimum_agreement", 2))
    services_raw = detection_raw.get("services", DEFAULT_IP_SERVICES)
    if not isinstance(services_raw, dict):
        raise ConfigError("ip_detection.services 必须是 JSON 对象")
    _warn_unknown_keys(services_raw, ("ipv4", "ipv6"), "ip_detection.services")
    services = {
        "ipv4": _validate_urls(
            services_raw.get("ipv4", DEFAULT_IP_SERVICES["ipv4"]),
            "ip_detection.services.ipv4",
            allow_insecure_http=allow_insecure_http,
        ),
        "ipv6": _validate_urls(
            services_raw.get("ipv6", DEFAULT_IP_SERVICES["ipv6"]),
            "ip_detection.services.ipv6",
            allow_insecure_http=allow_insecure_http,
        ),
    }

    api_bypass_proxy = _require_bool(
        cloudflare.get("bypass_proxy", False), "cloudflare.bypass_proxy"
    )
    create_missing = _require_bool(
        cloudflare.get("create_missing_records", True), "cloudflare.create_missing_records"
    )

    records_raw = raw.get("records")
    if not isinstance(records_raw, list) or not records_raw:
        raise ConfigError("records 必须是非空列表")
    records: List[Dict[str, Any]] = []
    seen: set[Tuple[str, str]] = set()
    for index, item in enumerate(records_raw):
        prefix = f"records[{index}]"
        if not isinstance(item, dict):
            raise ConfigError(f"{prefix} 必须是 JSON 对象")
        _warn_unknown_keys(item, ("name", "types", "ttl", "proxied", "comment"), prefix)
        if not isinstance(item.get("name"), str):
            raise ConfigError(f"{prefix}.name 必须是域名字符串")
        name = _ascii_domain(item["name"])
        if zone_name and name != zone_name and not name.endswith("." + zone_name):
            raise ConfigError(f"{prefix}.name ({name}) 不属于区域 {zone_name}")
        types = item.get("types", ["A"])
        if not isinstance(types, list) or not types:
            raise ConfigError(f"{prefix}.types 必须是包含 A 和/或 AAAA 的列表")
        normalized_types: List[str] = []
        for record_type in types:
            if not isinstance(record_type, str) or record_type.upper() not in ("A", "AAAA"):
                raise ConfigError(f"{prefix}.types 只支持 A 和 AAAA")
            upper = record_type.upper()
            key = (name, upper)
            if key in seen:
                raise ConfigError(f"重复记录: {upper} {name}")
            seen.add(key)
            normalized_types.append(upper)
        ttl = _require_int(item.get("ttl", 1), f"{prefix}.ttl", 1, 86400)
        if ttl != 1 and ttl < 60:
            raise ConfigError(f"{prefix}.ttl 必须是 1（自动）或 60-86400")
        proxied = _require_bool(item.get("proxied", False), f"{prefix}.proxied")
        if proxied and ttl != 1:
            raise ConfigError(f"{prefix}.ttl：Cloudflare 代理记录必须使用 1（自动 TTL）")
        comment = item.get("comment")
        if comment is not None and not isinstance(comment, str):
            raise ConfigError(f"{prefix}.comment 必须是字符串")
        records.append(
            {
                "name": name,
                "types": normalized_types,
                "ttl": ttl,
                "proxied": proxied,
                "comment": comment,
            }
        )

    for family, record_type in (("ipv4", "A"), ("ipv6", "AAAA")):
        if any(record_type in record["types"] for record in records):
            if consensus[family] > len(services[family]):
                raise ConfigError(
                    f"ip_detection.minimum_agreement.{family}={consensus[family]}，"
                    f"但 {family} 只有 {len(services[family])} 个服务"
                )

    return {
        "schema_version": CONFIG_SCHEMA_VERSION,
        "interval_seconds": interval,
        "request_timeout_seconds": timeout,
        "cloudflare": {
            "api_token_env": token_env,
            "api_token_file": token_file,
            "zone_id": zone_id.strip() if isinstance(zone_id, str) else None,
            "zone_name": zone_name,
            "bypass_proxy": api_bypass_proxy,
            "create_missing_records": create_missing,
        },
        "ip_detection": {
            "bypass_proxy": bypass_detection,
            "allow_insecure_http": allow_insecure_http,
            "source_diagnostics": source_diagnostics,
            "minimum_agreement": consensus,
            "services": services,
        },
        "records": records,
    }


def read_api_token(config: Mapping[str, Any], override: Optional[str] = None) -> str:
    if override is not None:
        token = override.strip()
        if token:
            return token
        raise ConfigError("从标准输入读取到的 API Token 为空")

    env_name = config["api_token_env"]
    token = os.environ.get(env_name, "").strip()
    if token:
        return token

    token_file = config.get("api_token_file")
    if token_file:
        path = Path(token_file).expanduser()
        try:
            mode = path.stat().st_mode
            if mode & stat.S_IROTH:
                LOG.warning("令牌文件 %s 可被所有本机用户读取，请收紧文件权限", path)
            token = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ConfigError(f"无法读取 API Token 文件 {path}: {exc}") from exc
        if token:
            return token
        raise ConfigError(f"API Token 文件为空: {path}")

    raise ConfigError(
        f"未找到 API Token：请设置环境变量 {env_name}，或配置 cloudflare.api_token_file"
    )


class SingleInstanceLock:
    """按实际 DNS 记录目标互斥，防止不同配置路径并发修改同一记录。"""

    def __init__(
        self,
        config_path: Path,
        config: Optional[Mapping[str, Any]] = None,
    ) -> None:
        identities: List[str] = []
        if config is not None:
            for record in config.get("records", []):
                name = str(record.get("name", "")).lower().rstrip(".")
                for record_type in record.get("types", []):
                    if name and record_type in ("A", "AAAA"):
                        identities.append(f"record:{record_type}:{name}")
        if not identities:
            try:
                resolved = str(config_path.resolve())
            except OSError:
                resolved = str(config_path)
            identities = [f"config:{resolved}"]

        uid = os.getuid() if hasattr(os, "getuid") else 0
        self.paths = [
            Path(tempfile.gettempdir())
            / f"cloudflare-ddns-{uid}-{hashlib.sha256(value.encode('utf-8')).hexdigest()[:16]}.lock"
            for value in sorted(set(identities))
        ]
        self.path = self.paths[0]
        self._handles: List[Any] = []

    def acquire(self) -> bool:
        """Return False when another process already holds any target lock."""
        if self._handles:
            return True
        acquired: List[Any] = []
        try:
            for path in self.paths:
                handle = open(path, "a+", encoding="utf-8")
                try:
                    if fcntl is not None:
                        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    elif msvcrt is not None:
                        handle.seek(0)
                        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        LOG.warning("当前平台不支持文件锁，跳过重复运行检测")
                except OSError:
                    handle.close()
                    raise BlockingIOError
                try:
                    handle.seek(0)
                    handle.truncate()
                    handle.write(str(os.getpid()))
                    handle.flush()
                except OSError:
                    pass
                acquired.append(handle)
        except BlockingIOError:
            for handle in acquired:
                self._unlock(handle)
            return False
        except OSError as exc:
            for handle in acquired:
                self._unlock(handle)
            LOG.warning("无法创建实例锁文件：%s；跳过重复运行检测", exc)
            return True
        self._handles = acquired
        return True

    def _unlock(self, handle: Any) -> None:
        try:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            elif msvcrt is not None:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
        handle.close()

    def release(self) -> None:
        handles, self._handles = self._handles, []
        for handle in handles:
            self._unlock(handle)
        # 锁文件本身保留：删除会与正在启动的进程产生竞态。


_NAT64_PREFIXES = (
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
)


def _is_global_unicast(address: Any) -> bool:
    if not address.is_global:
        return False
    if (
        address.is_multicast
        or address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_private
    ):
        return False
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return False
        if any(address in prefix for prefix in _NAT64_PREFIXES):
            return False
    return True


class PublicIPDetector:
    def __init__(
        self,
        services: Mapping[str, Sequence[str]],
        timeout: int,
        minimum_agreement: Any,
        bypass_proxy: bool = True,
        source_diagnostics: bool = False,
        opener: Optional[urllib.request.OpenerDirector] = None,
    ) -> None:
        self.services = services
        self.timeout = timeout
        if isinstance(minimum_agreement, Mapping):
            self.minimum_agreement = {
                "ipv4": int(minimum_agreement["ipv4"]),
                "ipv6": int(minimum_agreement["ipv6"]),
            }
        else:
            self.minimum_agreement = {
                "ipv4": int(minimum_agreement),
                "ipv6": int(minimum_agreement),
            }
        self.bypass_proxy = bypass_proxy
        self.source_diagnostics = source_diagnostics
        self.opener = opener or _make_opener(bypass_proxy)
        self._stats: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def _query(self, url: str, version: int) -> Tuple[str, str, float]:
        started = time.monotonic()
        request = urllib.request.Request(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "text/plain"},
        )
        with self.opener.open(request, timeout=self.timeout) as response:
            raw = response.read(256)
        if len(raw) >= 256:
            raise DetectionError("响应过长")
        try:
            text = raw.decode("utf-8").strip()
            address = ipaddress.ip_address(text)
        except (UnicodeDecodeError, ValueError) as exc:
            raise DetectionError("响应不是有效 IP 地址") from exc
        if address.version != version:
            raise DetectionError(f"返回了 IPv{address.version}，预期 IPv{version}")
        if not _is_global_unicast(address):
            raise DetectionError(f"拒绝非全球单播地址 {address}")
        return str(address), url, (time.monotonic() - started) * 1000.0

    def _record_source_result(
        self,
        family: str,
        url: str,
        *,
        elapsed_ms: float,
        address: Optional[str] = None,
        error: Optional[str] = None,
    ) -> None:
        stats = self._stats.setdefault(
            (family, url),
            {"requests": 0, "successes": 0, "total_ms": 0.0, "last_error": None},
        )
        stats["requests"] += 1
        stats["total_ms"] += elapsed_ms
        if address is not None:
            stats["successes"] += 1
            stats["last_error"] = None
        else:
            stats["last_error"] = error
        level = logging.INFO if self.source_diagnostics else logging.DEBUG
        success_rate = stats["successes"] / stats["requests"] * 100.0
        if address is not None:
            LOG.log(
                level,
                "%s 来源 %s：%s，%.0f ms，成功率 %.0f%%（%d/%d）",
                family.upper(),
                url,
                address,
                elapsed_ms,
                success_rate,
                stats["successes"],
                stats["requests"],
            )
        else:
            LOG.log(
                level,
                "%s 来源 %s：失败（%s），%.0f ms，成功率 %.0f%%（%d/%d）",
                family.upper(),
                url,
                error,
                elapsed_ms,
                success_rate,
                stats["successes"],
                stats["requests"],
            )

    def source_stats(self) -> List[Dict[str, Any]]:
        """Return JSON-friendly cumulative provider diagnostics for this process."""
        result: List[Dict[str, Any]] = []
        for (family, url), stats in sorted(self._stats.items()):
            requests = int(stats["requests"])
            result.append(
                {
                    "family": family,
                    "url": url,
                    "requests": requests,
                    "successes": int(stats["successes"]),
                    "success_rate": stats["successes"] / requests if requests else 0.0,
                    "average_ms": stats["total_ms"] / requests if requests else 0.0,
                    "last_error": stats["last_error"],
                }
            )
        return result

    def detect(self, family: str) -> str:
        if family not in ("ipv4", "ipv6"):
            raise ValueError(f"unknown address family: {family}")
        version = 4 if family == "ipv4" else 6
        urls = list(self.services[family])
        successes: List[Tuple[str, str]] = []
        failures: List[str] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(urls)) as pool:
            future_urls = {}
            future_starts = {}
            for url in urls:
                future = pool.submit(self._query, url, version)
                future_urls[future] = url
                future_starts[future] = time.monotonic()
            for future in concurrent.futures.as_completed(future_urls):
                url = future_urls[future]
                try:
                    address, source, elapsed_ms = future.result()
                    successes.append((address, source))
                    self._record_source_result(
                        family, source, elapsed_ms=elapsed_ms, address=address
                    )
                except Exception as exc:  # Each provider is an independent fallback.
                    elapsed_ms = (time.monotonic() - future_starts[future]) * 1000.0
                    failures.append(f"{url}: {exc}")
                    self._record_source_result(
                        family, url, elapsed_ms=elapsed_ms, error=str(exc)
                    )
                    LOG.debug("公网 IP 服务失败：%s: %s", url, exc)

        counts = Counter(address for address, _ in successes)
        if not counts:
            details = "; ".join(failures)
            raise DetectionError(f"所有 IPv{version} 查询服务均失败：{details}")
        ranked = counts.most_common()
        best_ip, best_count = ranked[0]
        required_agreement = self.minimum_agreement[family]
        if best_count < required_agreement:
            observed = ", ".join(f"{address}×{count}" for address, count in ranked)
            raise DetectionError(
                f"IPv{version} 查询结果未达到 {required_agreement} 票共识（{observed}）"
            )
        if len(ranked) > 1 and ranked[1][1] == best_count:
            observed = ", ".join(f"{address}×{count}" for address, count in ranked)
            raise DetectionError(f"IPv{version} 查询结果票数并列（{observed}）")
        LOG.info(
            "检测到公网 IPv%d：%s（%d/%d 个服务一致，绕过代理：%s）",
            version,
            best_ip,
            best_count,
            len(urls),
            "是" if self.bypass_proxy else "否",
        )
        _emit_event(
            "ip_detected",
            family=family,
            address=best_ip,
            votes=best_count,
            sources=len(urls),
        )
        return best_ip


def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    try:
        seconds = float(value.strip())
    except ValueError:
        return None  # HTTP 日期形式极少见，忽略后走指数退避
    return seconds if seconds >= 0 else None


def _retry_delay(error: CloudflareError, fallback: float) -> Optional[float]:
    """Pick the wait before a retry, or None when retrying is pointless."""
    if error.retry_after is not None:
        if error.retry_after > RETRY_AFTER_LIMIT:
            return None
        return max(1.0, error.retry_after)
    return fallback


class CloudflareClient:
    def __init__(
        self,
        api_token: str,
        timeout: int,
        bypass_proxy: bool = False,
        opener: Optional[urllib.request.OpenerDirector] = None,
    ) -> None:
        self.api_token = api_token
        self.timeout = timeout
        self.opener = opener or _make_opener(bypass_proxy)

    def request(
        self,
        method: str,
        path: str,
        query: Optional[Mapping[str, Any]] = None,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Any:
        # GET 幂等，可在本层直接重试；POST/PATCH 不能盲目重发——第一次请求
        # 可能已在服务端生效，由调用方重新查询记录后再决定（见 _sync_record）。
        retries = RETRY_BACKOFF_SECONDS if method.upper() == "GET" else ()
        attempt = 0
        while True:
            try:
                return self._request_once(method, path, query, payload)
            except CloudflareError as exc:
                delay = None
                if exc.retryable and attempt < len(retries):
                    delay = _retry_delay(exc, retries[attempt])
                if delay is None:
                    if retries:
                        exc.retryable = False  # 本层已经重试过，调用方无需再试
                    raise
                attempt += 1
                LOG.warning(
                    "Cloudflare API 请求失败，%.0f 秒后重试（第 %d/%d 次）：%s",
                    delay,
                    attempt,
                    len(retries),
                    exc,
                )
                time.sleep(delay)

    def _request_once(
        self,
        method: str,
        path: str,
        query: Optional[Mapping[str, Any]] = None,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Any:
        url = API_BASE + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.api_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            },
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read(MAX_CLOUDFLARE_RESPONSE_BYTES + 1)
                if len(raw) > MAX_CLOUDFLARE_RESPONSE_BYTES:
                    raise CloudflareError("Cloudflare API 响应超过 4 MiB 安全上限")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            message = self._error_message(body) or exc.reason
            retry_after = _parse_retry_after(exc.headers.get("Retry-After")) if exc.headers else None
            raise CloudflareError(
                f"Cloudflare API HTTP {exc.code}: {message}",
                status=exc.code,
                retryable=exc.code in RETRYABLE_HTTP_STATUS,
                retry_after=retry_after,
            ) from exc
        except urllib.error.URLError as exc:
            raise CloudflareError(f"无法连接 Cloudflare API: {exc.reason}", retryable=True) from exc
        except (TimeoutError, socket.timeout) as exc:
            raise CloudflareError("连接 Cloudflare API 超时", retryable=True) from exc

        try:
            document = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise CloudflareError("Cloudflare API 返回了无效 JSON") from exc
        if not isinstance(document, dict) or document.get("success") is not True:
            message = self._errors_from_document(document) or "未知 API 错误"
            raise CloudflareError(f"Cloudflare API 请求失败: {message}")
        return document.get("result")

    @staticmethod
    def _errors_from_document(document: Any) -> str:
        if not isinstance(document, dict):
            return ""
        messages = []
        for error in document.get("errors", []):
            if isinstance(error, dict):
                code = error.get("code")
                message = error.get("message", "未知错误")
                messages.append(f"[{code}] {message}" if code is not None else str(message))
        return "; ".join(messages)

    @classmethod
    def _error_message(cls, body: str) -> str:
        try:
            return cls._errors_from_document(json.loads(body))
        except (json.JSONDecodeError, TypeError):
            return body[:200].strip()

    def find_zone_id(self, zone_name: str) -> str:
        result = self.request("GET", "/zones", {"name": zone_name, "per_page": 50})
        if not isinstance(result, list):
            raise CloudflareError("Cloudflare API 的区域列表格式异常")
        exact = [
            zone
            for zone in result
            if isinstance(zone, dict)
            and isinstance(zone.get("name"), str)
            and _ascii_domain(zone["name"]) == zone_name
        ]
        if not exact:
            raise CloudflareError(
                f"找不到 Cloudflare 区域 {zone_name}；请检查区域名以及 Token 的 Zone Read 权限"
            )
        if len(exact) > 1:
            raise CloudflareError(f"区域 {zone_name} 返回了多个匹配项，请直接配置 zone_id")
        zone_id = exact[0].get("id")
        if not isinstance(zone_id, str) or not zone_id:
            raise CloudflareError("Cloudflare API 返回的区域缺少 ID")
        return zone_id

    def verify_token(self) -> Dict[str, Any]:
        result = self.request("GET", "/user/tokens/verify")
        if not isinstance(result, dict):
            raise CloudflareError("Cloudflare Token 验证响应格式异常")
        status = result.get("status")
        if status != "active":
            raise CloudflareError(f"Cloudflare Token 状态不是 active：{status or '未知'}")
        return result

    def list_zones(self) -> List[Dict[str, Any]]:
        zones: List[Dict[str, Any]] = []
        page = 1
        per_page = 50
        while True:
            result = self.request(
                "GET", "/zones", {"per_page": per_page, "page": page, "order": "name"}
            )
            if not isinstance(result, list):
                raise CloudflareError("Cloudflare API 的区域列表格式异常")
            zones.extend(item for item in result if isinstance(item, dict))
            if len(result) < per_page:
                return zones
            page += 1

    def list_records(self, zone_id: str, name: str, record_type: str) -> List[Dict[str, Any]]:
        result = self.request(
            "GET",
            f"/zones/{urllib.parse.quote(zone_id, safe='')}/dns_records",
            {"name": name, "type": record_type, "per_page": 100},
        )
        if not isinstance(result, list):
            raise CloudflareError("Cloudflare API 的 DNS 记录列表格式异常")
        # Keep an exact local filter even if an older API treats name as a search term.
        return [
            record
            for record in result
            if isinstance(record, dict)
            and isinstance(record.get("name"), str)
            and record["name"].lower().rstrip(".") == name
            and record.get("type") == record_type
        ]

    def list_type_records(self, zone_id: str, record_type: str) -> List[Dict[str, Any]]:
        """一次性拉取区域内某类型的全部记录（自动翻页），供本地索引使用。"""
        records: List[Dict[str, Any]] = []
        page = 1
        per_page = 100
        while True:
            result = self.request(
                "GET",
                f"/zones/{urllib.parse.quote(zone_id, safe='')}/dns_records",
                {"type": record_type, "per_page": per_page, "page": page},
            )
            if not isinstance(result, list):
                raise CloudflareError("Cloudflare API 的 DNS 记录列表格式异常")
            records.extend(item for item in result if isinstance(item, dict))
            if len(result) < per_page:
                return records
            page += 1

    def create_record(self, zone_id: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        result = self.request(
            "POST",
            f"/zones/{urllib.parse.quote(zone_id, safe='')}/dns_records",
            payload=payload,
        )
        if not isinstance(result, dict):
            raise CloudflareError("Cloudflare API 的新建记录响应格式异常")
        return result

    def edit_record(
        self, zone_id: str, record_id: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        result = self.request(
            "PATCH",
            f"/zones/{urllib.parse.quote(zone_id, safe='')}/dns_records/"
            f"{urllib.parse.quote(record_id, safe='')}",
            payload=payload,
        )
        if not isinstance(result, dict):
            raise CloudflareError("Cloudflare API 的更新记录响应格式异常")
        return result


def _ip_equal(first: Any, second: str) -> bool:
    try:
        return ipaddress.ip_address(str(first)) == ipaddress.ip_address(second)
    except ValueError:
        return False


def _record_changes(current: Mapping[str, Any], desired: Mapping[str, Any]) -> Dict[str, Any]:
    changes: Dict[str, Any] = {}
    if not _ip_equal(current.get("content"), str(desired["content"])):
        changes["content"] = desired["content"]
    if current.get("ttl") != desired["ttl"]:
        changes["ttl"] = desired["ttl"]
    if current.get("proxied") != desired["proxied"]:
        changes["proxied"] = desired["proxied"]
    if "comment" in desired and current.get("comment", "") != desired["comment"]:
        changes["comment"] = desired["comment"]
    return changes


class DDNSUpdater:
    def __init__(
        self,
        config: Mapping[str, Any],
        detector: PublicIPDetector,
        client: CloudflareClient,
        dry_run: bool = False,
    ) -> None:
        self.config = config
        self.detector = detector
        self.client = client
        self.dry_run = dry_run
        self._zone_id: Optional[str] = config["cloudflare"].get("zone_id")
        # 连续检测失败计数；只在常驻循环模式下跨周期累积（--once 每次都是新进程）。
        self._detection_failures: Dict[str, int] = {"A": 0, "AAAA": 0}

    def _get_zone_id(self) -> str:
        if not self._zone_id:
            zone_name = self.config["cloudflare"].get("zone_name")
            self._zone_id = self.client.find_zone_id(zone_name)
            LOG.info("区域 %s 的 ID：%s", zone_name, self._zone_id)
        return self._zone_id

    def _detect_addresses(self, required_types: set[str]) -> Tuple[Dict[str, str], bool]:
        wanted = [
            (record_type, family)
            for record_type, family in (("A", "ipv4"), ("AAAA", "ipv6"))
            if record_type in required_types
        ]
        addresses: Dict[str, str] = {}
        ok = True
        if not wanted:
            return addresses, ok
        # A 与 AAAA 并行检测：IPv6 不通时不再拖长整体等待时间。
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(wanted)) as pool:
            futures = {
                record_type: pool.submit(self.detector.detect, family)
                for record_type, family in wanted
            }
            for record_type, family in wanted:
                version = 4 if family == "ipv4" else 6
                try:
                    addresses[record_type] = futures[record_type].result()
                    self._detection_failures[record_type] = 0
                except DetectionError as exc:
                    ok = False
                    failures = self._detection_failures[record_type] + 1
                    self._detection_failures[record_type] = failures
                    LOG.error("IPv%s 检测失败，本轮保留现有 %s 记录：%s", version, record_type, exc)
                    _emit_event(
                        "ip_detection_failed",
                        family=family,
                        record_type=record_type,
                        consecutive_failures=failures,
                        message=str(exc),
                    )
                    if failures >= STALE_RECORD_WARNING_THRESHOLD:
                        LOG.warning(
                            "IPv%s 已连续 %d 次检测失败，Cloudflare 上的 %s 记录可能指向失效地址；"
                            "确认该网络已停用后，请在 Cloudflare 手动删除或停用相应记录",
                            version,
                            failures,
                            record_type,
                        )
        return addresses, ok

    def _sync_record(
        self,
        zone_id: str,
        record: Mapping[str, Any],
        record_type: str,
        address: str,
        current_records: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        name = record["name"]
        attempt = 0
        while True:
            if current_records is None:
                current_records = self.client.list_records(zone_id, name, record_type)
            try:
                self._apply_record(zone_id, record, record_type, address, current_records)
                return
            except CloudflareError as exc:
                delay = None
                if exc.retryable and attempt < len(RETRY_BACKOFF_SECONDS):
                    delay = _retry_delay(exc, RETRY_BACKOFF_SECONDS[attempt])
                if delay is None:
                    raise
                attempt += 1
                LOG.warning(
                    "写入 %s %s 失败，%.0f 秒后重新查询并重试（第 %d/%d 次）：%s",
                    record_type,
                    name,
                    delay,
                    attempt,
                    len(RETRY_BACKOFF_SECONDS),
                    exc,
                )
                time.sleep(delay)
                # 上一次写请求可能已在服务端生效；重查最新状态，避免重复创建记录。
                current_records = None

    def _apply_record(
        self,
        zone_id: str,
        record: Mapping[str, Any],
        record_type: str,
        address: str,
        current_records: List[Dict[str, Any]],
    ) -> None:
        name = record["name"]
        if len(current_records) > 1:
            raise CloudflareError(
                f"发现多个同名 {record_type} 记录：{name}；为避免误改，请先在 Cloudflare 清理重复项"
            )

        desired: Dict[str, Any] = {
            "type": record_type,
            "name": name,
            "content": address,
            "ttl": record["ttl"],
            "proxied": record["proxied"],
        }
        if record.get("comment") is not None:
            desired["comment"] = record["comment"]

        if not current_records:
            if not self.config["cloudflare"]["create_missing_records"]:
                raise CloudflareError(f"记录不存在且禁止自动创建：{record_type} {name}")
            if self.dry_run:
                LOG.info("[演练] 将创建 %s %s -> %s", record_type, name, address)
                _emit_event(
                    "record_change", action="create", dry_run=True,
                    record_type=record_type, name=name, address=address,
                )
            else:
                self.client.create_record(zone_id, desired)
                LOG.info("已创建 %s %s -> %s", record_type, name, address)
                _emit_event(
                    "record_change", action="create", dry_run=False,
                    record_type=record_type, name=name, address=address,
                )
            return

        current = current_records[0]
        changes = _record_changes(current, desired)
        if not changes:
            LOG.info("无需更新 %s %s（%s）", record_type, name, address)
            _emit_event(
                "record_unchanged", record_type=record_type, name=name, address=address
            )
            return
        if self.dry_run:
            LOG.info("[演练] 将更新 %s %s：%s", record_type, name, changes)
            _emit_event(
                "record_change", action="update", dry_run=True,
                record_type=record_type, name=name, address=address, changes=changes,
            )
        else:
            # PATCH only touches managed fields and preserves tags/settings.
            record_id = current.get("id")
            if not isinstance(record_id, str) or not record_id:
                raise CloudflareError(f"Cloudflare API 返回的 {record_type} {name} 记录缺少 ID")
            self.client.edit_record(zone_id, record_id, changes)
            LOG.info("已更新 %s %s -> %s", record_type, name, address)
            _emit_event(
                "record_change", action="update", dry_run=False,
                record_type=record_type, name=name, address=address, changes=changes,
            )

    def run_once(self) -> bool:
        LOG.info("开始 DDNS 检查")
        required_types = {
            record_type
            for record in self.config["records"]
            for record_type in record["types"]
        }
        addresses, ok = self._detect_addresses(required_types)
        if not addresses:
            return False

        try:
            zone_id = self._get_zone_id()
        except CloudflareError as exc:
            LOG.error("无法确定 Cloudflare 区域：%s", exc)
            return False

        # 每种类型一次性拉取全区域记录并建立本地索引，避免逐条记录请求列表。
        index: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        listed_types: set[str] = set()
        for record_type in sorted(addresses):
            try:
                for item in self.client.list_type_records(zone_id, record_type):
                    item_name = item.get("name")
                    if isinstance(item_name, str) and item.get("type") == record_type:
                        key = (item_name.lower().rstrip("."), record_type)
                        index.setdefault(key, []).append(item)
                listed_types.add(record_type)
            except CloudflareError as exc:
                ok = False
                LOG.error("获取 %s 记录列表失败，本轮跳过该类型：%s", record_type, exc)

        for record in self.config["records"]:
            for record_type in record["types"]:
                address = addresses.get(record_type)
                if not address or record_type not in listed_types:
                    continue
                current = index.get((record["name"], record_type), [])
                try:
                    self._sync_record(zone_id, record, record_type, address, current)
                except CloudflareError as exc:
                    ok = False
                    LOG.error("同步 %s %s 失败：%s", record_type, record["name"], exc)
        return ok


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="绕过本机 HTTP 代理检测公网 IP，并同步到 Cloudflare DNS。"
    )
    parser.add_argument(
        "-c", "--config", type=Path, default=Path("config.json"), help="配置文件（默认：./config.json）"
    )
    parser.add_argument("--once", action="store_true", help="只执行一次，不进入定时循环")
    parser.add_argument("--dry-run", action="store_true", help="查询并显示变更，但不写入 Cloudflare")
    parser.add_argument("--check-ip", action="store_true", help="只检测公网 IP，不访问 Cloudflare")
    parser.add_argument(
        "--source-diagnostics",
        action="store_true",
        help="输出每个公网 IP 来源的耗时与进程内成功率",
    )
    parser.add_argument(
        "--json-events",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--api-token-stdin",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--test-connection",
        action="store_true",
        help="验证 Token、区域权限和 DNS 记录读取权限，不写入 Cloudflare",
    )
    parser.add_argument(
        "--discover",
        action="store_true",
        help="使用 CLOUDFLARE_API_TOKEN 发现可访问区域，并以 JSON 输出",
    )
    parser.add_argument(
        "--discover-zone-id",
        help="与 --discover 一起使用，同时列出指定区域的 A/AAAA 记录",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="输出各 IP 服务的失败详情")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _needed_families(config: Mapping[str, Any]) -> Iterable[Tuple[str, str]]:
    record_types = {
        record_type for record in config["records"] for record_type in record["types"]
    }
    if "A" in record_types:
        yield "ipv4", "IPv4"
    if "AAAA" in record_types:
        yield "ipv6", "IPv6"


def _discovery_document(client: CloudflareClient, zone_id: Optional[str]) -> Dict[str, Any]:
    verification = client.verify_token()
    zones = []
    for zone in client.list_zones():
        identifier = zone.get("id")
        name = zone.get("name")
        if isinstance(identifier, str) and isinstance(name, str):
            zones.append({"id": identifier, "name": name, "status": zone.get("status")})

    records: List[Dict[str, Any]] = []
    if zone_id:
        for record_type in ("A", "AAAA"):
            for record in client.list_type_records(zone_id, record_type):
                records.append(
                    {
                        key: record.get(key)
                        for key in ("id", "name", "type", "content", "ttl", "proxied", "comment")
                    }
                )
    return {
        "token": {"id": verification.get("id"), "status": verification.get("status")},
        "zones": zones,
        "records": records,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    global JSON_EVENTS_ENABLED
    args = _build_parser().parse_args(argv)
    JSON_EVENTS_ENABLED = args.json_events
    _configure_logging(args.verbose)
    stdin_token = sys.stdin.readline().strip() if args.api_token_stdin else None

    if args.discover:
        token = stdin_token or os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
        if not token:
            LOG.error("发现区域需要环境变量 CLOUDFLARE_API_TOKEN")
            return 2
        try:
            discovery_client = CloudflareClient(token, timeout=15)
            print(
                json.dumps(
                    _discovery_document(discovery_client, args.discover_zone_id),
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
            return 0
        except CloudflareError as exc:
            LOG.error("Cloudflare 连接测试失败：%s", exc)
            return 1

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        LOG.error("配置错误：%s", exc)
        return 2

    detection = config["ip_detection"]
    detector = PublicIPDetector(
        services=detection["services"],
        timeout=config["request_timeout_seconds"],
        minimum_agreement=detection["minimum_agreement"],
        bypass_proxy=detection["bypass_proxy"],
        source_diagnostics=(
            args.source_diagnostics or args.verbose or detection["source_diagnostics"]
        ),
    )

    if args.check_ip:
        success = True
        for family, label in _needed_families(config):
            try:
                address = detector.detect(family)
                print(f"{label}: {address}")
            except DetectionError as exc:
                success = False
                LOG.error("%s 检测失败：%s", label, exc)
        return 0 if success else 1

    lock: Optional[SingleInstanceLock] = None
    if not args.dry_run and not args.test_connection:
        # 互斥锁按配置文件路径建立：GUI、launchd/systemd 或手动命令重复启动时，
        # 后启动的实例直接提示并退出，避免两个进程同时创建/修改同一批记录。
        # --dry-run 与 --check-ip 只读，不参与互斥。
        lock = SingleInstanceLock(args.config, config=config)
        if not lock.acquire():
            LOG.error(
                "检测到另一个实例正在使用同一配置运行（%s）；为避免并发修改，本实例退出",
                args.config,
            )
            return 3

    try:
        try:
            api_token = read_api_token(config["cloudflare"], override=stdin_token)
        except ConfigError as exc:
            LOG.error("配置错误：%s", exc)
            return 2

        cloudflare = config["cloudflare"]
        client = CloudflareClient(
            api_token=api_token,
            timeout=config["request_timeout_seconds"],
            bypass_proxy=cloudflare["bypass_proxy"],
        )
        updater = DDNSUpdater(config, detector, client, dry_run=args.dry_run)

        if args.test_connection:
            try:
                verification = client.verify_token()
                zone_id = updater._get_zone_id()
                counts = {}
                for record_type in sorted(
                    {item for record in config["records"] for item in record["types"]}
                ):
                    counts[record_type] = len(client.list_type_records(zone_id, record_type))
                print(
                    json.dumps(
                        {
                            "token_status": verification.get("status"),
                            "zone_id": zone_id,
                            "record_counts": counts,
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    )
                )
                LOG.info("Cloudflare 连接、Token、区域和 DNS 读取权限正常；DNS Edit 权限将在首次实际同步时验证")
                return 0
            except CloudflareError as exc:
                LOG.error("Cloudflare 连接测试失败：%s", exc)
                return 1

        if args.once:
            try:
                return 0 if updater.run_once() else 1
            except Exception:
                LOG.exception("DDNS 检查遇到未预期错误")
                return 1

        stop_event = threading.Event()

        def stop(signum: int, _frame: Any) -> None:
            LOG.info("收到信号 %s，准备退出", signum)
            stop_event.set()

        for signal_name in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signal_name, stop)

        LOG.info("DDNS 服务已启动，每 %d 秒检查一次", config["interval_seconds"])
        while not stop_event.is_set():
            started = time.monotonic()
            try:
                updater.run_once()
            except Exception:
                # A malformed remote response or an unforeseen error must not kill
                # a long-running DDNS service; the next interval retries safely.
                LOG.exception("DDNS 检查遇到未预期错误，下个周期将重试")
            elapsed = time.monotonic() - started
            wait_seconds = max(1.0, config["interval_seconds"] - elapsed)
            stop_event.wait(wait_seconds)
        LOG.info("DDNS 服务已停止")
        return 0
    finally:
        if lock is not None:
            lock.release()


if __name__ == "__main__":
    sys.exit(main())
