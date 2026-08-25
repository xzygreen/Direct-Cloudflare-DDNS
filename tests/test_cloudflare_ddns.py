import json
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

import cloudflare_ddns as ddns


class FakeResponse:
    def __init__(self, data):
        self.data = data if isinstance(data, bytes) else data.encode("utf-8")

    def read(self, _size=-1):
        return self.data

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def close(self):
        pass


class IPFakeOpener:
    def __init__(self, values):
        self.values = values

    def open(self, request, timeout):
        del timeout
        value = self.values[request.full_url]
        if isinstance(value, Exception):
            raise value
        return FakeResponse(value)


class QueueOpener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def open(self, request, timeout):
        del timeout
        self.requests.append(request)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return FakeResponse(json.dumps(response))


def minimal_config():
    return {
        "cloudflare": {
            "zone_id": "zone-id",
            "zone_name": "example.com",
            "create_missing_records": True,
        },
        "records": [
            {
                "name": "home.example.com",
                "types": ["A"],
                "ttl": 1,
                "proxied": False,
                "comment": None,
            }
        ],
    }


def http_error(code, headers=None, body=b"{}"):
    return urllib.error.HTTPError(
        "https://api.test", code, "server error", headers or {}, FakeResponse(body)
    )


class ConfigTests(unittest.TestCase):
    def write_config(self, document):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "config.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def valid_document(self):
        return {
            "cloudflare": {"zone_name": "例子.com"},
            "records": [{"name": "家.例子.com", "types": ["a"]}],
        }

    def test_loads_defaults_and_idna(self):
        config = ddns.load_config(self.write_config(self.valid_document()))
        self.assertEqual(config["schema_version"], 2)
        self.assertEqual(config["cloudflare"]["zone_name"], "xn--fsqu00a.com")
        self.assertEqual(config["records"][0]["name"], "xn--fct.xn--fsqu00a.com")
        self.assertEqual(config["records"][0]["types"], ["A"])
        self.assertTrue(config["ip_detection"]["bypass_proxy"])
        self.assertEqual(
            config["ip_detection"]["minimum_agreement"], {"ipv4": 2, "ipv6": 2}
        )

    def test_accepts_per_family_agreement(self):
        document = self.valid_document()
        document["ip_detection"] = {
            "minimum_agreement": {"ipv4": 1, "ipv6": 3}
        }
        config = ddns.load_config(self.write_config(document))
        self.assertEqual(config["ip_detection"]["minimum_agreement"]["ipv4"], 1)

    def test_rejects_duplicate_ip_sources(self):
        document = self.valid_document()
        document["ip_detection"] = {
            "services": {
                "ipv4": ["https://one.test", "https://one.test"],
                "ipv6": ["https://v6.test", "https://v6b.test"],
            }
        }
        with self.assertRaisesRegex(ddns.ConfigError, "重复查询服务"):
            ddns.load_config(self.write_config(document))

    def test_http_source_requires_explicit_opt_in(self):
        document = self.valid_document()
        document["ip_detection"] = {
            "services": {
                "ipv4": ["http://one.test", "https://two.test"],
                "ipv6": ["https://v6.test", "https://v6b.test"],
            }
        }
        with self.assertRaisesRegex(ddns.ConfigError, "不安全的 HTTP"):
            ddns.load_config(self.write_config(document))
        document["ip_detection"]["allow_insecure_http"] = True
        with self.assertLogs("cloudflare-ddns", level="WARNING"):
            ddns.load_config(self.write_config(document))

    def test_rejects_future_schema(self):
        document = self.valid_document()
        document["schema_version"] = ddns.CONFIG_SCHEMA_VERSION + 1
        with self.assertRaisesRegex(ddns.ConfigError, "请升级程序"):
            ddns.load_config(self.write_config(document))

    def test_rejects_record_outside_zone(self):
        document = self.valid_document()
        document["records"][0]["name"] = "other.net"
        with self.assertRaisesRegex(ddns.ConfigError, "不属于区域"):
            ddns.load_config(self.write_config(document))

    def test_rejects_duplicate_record(self):
        document = self.valid_document()
        document["records"].append({"name": "家.例子.com", "types": ["A"]})
        with self.assertRaisesRegex(ddns.ConfigError, "重复记录"):
            ddns.load_config(self.write_config(document))

    def test_proxied_record_requires_automatic_ttl(self):
        document = self.valid_document()
        document["records"][0].update({"proxied": True, "ttl": 300})
        with self.assertRaisesRegex(ddns.ConfigError, "自动 TTL"):
            ddns.load_config(self.write_config(document))

    def test_rejects_malformed_labels(self):
        for bad in ("ho me.example.com", "-home.example.com", "home-.example.com", "a.*.example.com"):
            with self.subTest(bad=bad):
                document = {
                    "cloudflare": {"zone_name": "example.com"},
                    "records": [{"name": bad, "types": ["A"]}],
                }
                with self.assertRaisesRegex(ddns.ConfigError, "无效域名"):
                    ddns.load_config(self.write_config(document))

    def test_warns_on_unknown_keys(self):
        document = self.valid_document()
        document["unknown_top"] = 1
        document["cloudflare"]["zone"] = "typo"
        document["records"][0]["proxy"] = True  # proxied 的常见拼写错误
        with self.assertLogs("cloudflare-ddns", level="WARNING") as logs:
            ddns.load_config(self.write_config(document))
        joined = "\n".join(logs.output)
        self.assertIn("unknown_top", joined)
        self.assertIn("zone", joined)
        self.assertIn("proxy", joined)

    def test_token_prefers_environment(self):
        with mock.patch.dict(os.environ, {"SPECIAL_CF_TOKEN": " secret "}, clear=False):
            token = ddns.read_api_token(
                {"api_token_env": "SPECIAL_CF_TOKEN", "api_token_file": "/not/read"}
            )
        self.assertEqual(token, "secret")


class DetectorTests(unittest.TestCase):
    def detector(self, values, agreement=2):
        services = {"ipv4": list(values), "ipv6": ["https://v6.test"]}
        return ddns.PublicIPDetector(
            services,
            timeout=1,
            minimum_agreement=agreement,
            bypass_proxy=True,
            opener=IPFakeOpener(values),
        )

    def test_consensus_wins(self):
        values = {
            "https://one.test": "8.8.8.8\n",
            "https://two.test": "8.8.8.8",
            "https://three.test": "1.1.1.1",
        }
        self.assertEqual(self.detector(values).detect("ipv4"), "8.8.8.8")

    def test_source_stats_include_latency_and_rate(self):
        values = {"https://one.test": "8.8.8.8"}
        detector = self.detector(values, agreement=1)
        detector.detect("ipv4")
        stats = detector.source_stats()
        self.assertEqual(stats[0]["successes"], 1)
        self.assertEqual(stats[0]["success_rate"], 1.0)
        self.assertGreaterEqual(stats[0]["average_ms"], 0)

    def test_private_address_is_rejected(self):
        values = {
            "https://one.test": "192.168.1.2",
            "https://two.test": "10.0.0.1",
        }
        with self.assertRaisesRegex(ddns.DetectionError, "所有 IPv4"):
            self.detector(values).detect("ipv4")

    def test_disagreement_does_not_update(self):
        values = {
            "https://one.test": "8.8.8.8",
            "https://two.test": "1.1.1.1",
            "https://three.test": "9.9.9.9",
        }
        with self.assertRaisesRegex(ddns.DetectionError, "未达到 2 票共识"):
            self.detector(values).detect("ipv4")

    def test_wrong_ip_family_is_rejected(self):
        values = {"https://one.test": "2606:4700:4700::1111"}
        with self.assertRaisesRegex(ddns.DetectionError, "所有 IPv4"):
            self.detector(values, agreement=1).detect("ipv4")

    def test_direct_opener_installs_empty_proxy_handler(self):
        with mock.patch("urllib.request.build_opener") as build:
            ddns._direct_opener()
        handler = build.call_args.args[0]
        self.assertIsInstance(handler, ddns.urllib.request.ProxyHandler)
        self.assertEqual(handler.proxies, {})


class CloudflareClientTests(unittest.TestCase):
    def test_request_uses_bearer_and_json(self):
        opener = QueueOpener([{"success": True, "result": {"id": "record-id"}}])
        client = ddns.CloudflareClient("token-value", 3, opener=opener)
        result = client.request("PATCH", "/test", payload={"content": "8.8.8.8"})
        request = opener.requests[0]
        self.assertEqual(result["id"], "record-id")
        self.assertEqual(request.get_method(), "PATCH")
        self.assertEqual(request.get_header("Authorization"), "Bearer token-value")
        self.assertEqual(json.loads(request.data), {"content": "8.8.8.8"})

    def test_api_error_is_readable(self):
        body = json.dumps(
            {"success": False, "errors": [{"code": 9109, "message": "Invalid token"}]}
        ).encode()
        error = urllib.error.HTTPError("https://api.test", 403, "Forbidden", {}, FakeResponse(body))
        client = ddns.CloudflareClient("bad", 3, opener=QueueOpener([error]))
        with self.assertRaisesRegex(ddns.CloudflareError, r"\[9109\] Invalid token"):
            client.request("GET", "/test")

    def test_record_changes_preserve_unmanaged_comment(self):
        current = {
            "content": "1.1.1.1",
            "ttl": 1,
            "proxied": False,
            "comment": "keep this",
        }
        desired = {"content": "8.8.8.8", "ttl": 1, "proxied": False}
        self.assertEqual(ddns._record_changes(current, desired), {"content": "8.8.8.8"})

    def test_get_retries_on_server_error(self):
        opener = QueueOpener([http_error(503), {"success": True, "result": []}])
        client = ddns.CloudflareClient("token", 3, opener=opener)
        with mock.patch.object(ddns.time, "sleep") as fake_sleep:
            result = client.request("GET", "/zones")
        self.assertEqual(result, [])
        self.assertEqual(len(opener.requests), 2)
        fake_sleep.assert_called_once_with(1.0)

    def test_retry_after_header_is_honored(self):
        opener = QueueOpener(
            [http_error(429, {"Retry-After": "2"}), {"success": True, "result": []}]
        )
        client = ddns.CloudflareClient("token", 3, opener=opener)
        with mock.patch.object(ddns.time, "sleep") as fake_sleep:
            client.request("GET", "/zones")
        fake_sleep.assert_called_once_with(2.0)

    def test_excessive_retry_after_gives_up(self):
        opener = QueueOpener([http_error(429, {"Retry-After": "600"})])
        client = ddns.CloudflareClient("token", 3, opener=opener)
        with mock.patch.object(ddns.time, "sleep") as fake_sleep:
            with self.assertRaises(ddns.CloudflareError) as ctx:
                client.request("GET", "/zones")
        self.assertEqual(len(opener.requests), 1)
        self.assertFalse(ctx.exception.retryable)
        fake_sleep.assert_not_called()

    def test_get_gives_up_after_exhausting_retries(self):
        opener = QueueOpener([http_error(500) for _ in range(4)])
        client = ddns.CloudflareClient("token", 3, opener=opener)
        with mock.patch.object(ddns.time, "sleep") as fake_sleep:
            with self.assertRaises(ddns.CloudflareError) as ctx:
                client.request("GET", "/zones")
        self.assertEqual(len(opener.requests), 4)
        self.assertFalse(ctx.exception.retryable)
        self.assertEqual(
            [call.args[0] for call in fake_sleep.call_args_list], [1.0, 2.0, 4.0]
        )

    def test_post_is_not_retried_but_flagged_retryable(self):
        opener = QueueOpener([http_error(502)])
        client = ddns.CloudflareClient("token", 3, opener=opener)
        with mock.patch.object(ddns.time, "sleep") as fake_sleep:
            with self.assertRaises(ddns.CloudflareError) as ctx:
                client.request("POST", "/zones/z/dns_records", payload={})
        self.assertEqual(len(opener.requests), 1)
        self.assertTrue(ctx.exception.retryable)
        fake_sleep.assert_not_called()

    def test_list_type_records_paginates(self):
        page1 = [
            {"id": str(i), "type": "A", "name": f"h{i}.example.com"} for i in range(100)
        ]
        page2 = [{"id": "last", "type": "A", "name": "last.example.com"}]
        opener = QueueOpener(
            [{"success": True, "result": page1}, {"success": True, "result": page2}]
        )
        client = ddns.CloudflareClient("token", 3, opener=opener)
        records = client.list_type_records("zone", "A")
        self.assertEqual(len(records), 101)
        self.assertEqual(len(opener.requests), 2)
        self.assertIn("page=2", opener.requests[1].full_url)

    def test_discovery_verifies_token_and_filters_fields(self):
        opener = QueueOpener(
            [
                {"success": True, "result": {"id": "token", "status": "active"}},
                {
                    "success": True,
                    "result": [{"id": "zone", "name": "example.com", "status": "active"}],
                },
                {
                    "success": True,
                    "result": [{"id": "a", "type": "A", "name": "home.example.com"}],
                },
                {"success": True, "result": []},
            ]
        )
        client = ddns.CloudflareClient("token", 3, opener=opener)
        document = ddns._discovery_document(client, "zone")
        self.assertEqual(document["token"]["status"], "active")
        self.assertEqual(document["zones"][0]["name"], "example.com")
        self.assertEqual(document["records"][0]["type"], "A")


class FakeDetector:
    def __init__(self, address="8.8.8.8", error=None):
        self.address = address
        self.error = error

    def detect(self, _family):
        if self.error:
            raise self.error
        return self.address


class FakeCloudflareClient:
    def __init__(self, records=None):
        self.records = [] if records is None else records
        self.created = []
        self.edited = []

    def find_zone_id(self, _zone_name):
        return "found-zone"

    def list_type_records(self, _zone_id, record_type):
        return [dict(r) for r in self.records if r.get("type") == record_type]

    def list_records(self, _zone_id, name, record_type):
        return [
            dict(r)
            for r in self.records
            if r.get("type") == record_type and r.get("name") == name
        ]

    def create_record(self, zone_id, payload):
        self.created.append((zone_id, payload))
        return dict(payload)

    def edit_record(self, zone_id, record_id, payload):
        self.edited.append((zone_id, record_id, payload))
        return dict(payload)


class TimeoutThenExistsClient(FakeCloudflareClient):
    """首次创建请求超时，但记录实际已在服务端生效。"""

    def __init__(self):
        super().__init__()
        self.list_calls = 0
        self._failed_once = False

    def list_records(self, zone_id, name, record_type):
        self.list_calls += 1
        return super().list_records(zone_id, name, record_type)

    def create_record(self, zone_id, payload):
        if not self._failed_once:
            self._failed_once = True
            self.records.append(
                {
                    "id": "server-side",
                    "name": payload["name"],
                    "type": payload["type"],
                    "content": payload["content"],
                    "ttl": payload["ttl"],
                    "proxied": payload["proxied"],
                }
            )
            raise ddns.CloudflareError("连接 Cloudflare API 超时", retryable=True)
        return super().create_record(zone_id, payload)


class UpdaterTests(unittest.TestCase):
    def existing_record(self, content="1.1.1.1"):
        return {
            "id": "record",
            "name": "home.example.com",
            "type": "A",
            "content": content,
            "ttl": 1,
            "proxied": False,
        }

    def test_creates_missing_record(self):
        client = FakeCloudflareClient()
        updater = ddns.DDNSUpdater(minimal_config(), FakeDetector(), client)
        self.assertTrue(updater.run_once())
        self.assertEqual(client.created[0][1]["content"], "8.8.8.8")

    def test_dry_run_does_not_create(self):
        client = FakeCloudflareClient()
        updater = ddns.DDNSUpdater(minimal_config(), FakeDetector(), client, dry_run=True)
        self.assertTrue(updater.run_once())
        self.assertEqual(client.created, [])

    def test_detection_error_preserves_record(self):
        client = FakeCloudflareClient([self.existing_record()])
        detector = FakeDetector(error=ddns.DetectionError("offline"))
        updater = ddns.DDNSUpdater(minimal_config(), detector, client)
        self.assertFalse(updater.run_once())
        self.assertEqual(client.edited, [])

    def test_updates_only_changed_content(self):
        client = FakeCloudflareClient([self.existing_record()])
        updater = ddns.DDNSUpdater(minimal_config(), FakeDetector(), client)
        self.assertTrue(updater.run_once())
        self.assertEqual(client.edited, [("zone-id", "record", {"content": "8.8.8.8"})])

    def test_write_retry_requeries_instead_of_duplicating(self):
        client = TimeoutThenExistsClient()
        updater = ddns.DDNSUpdater(minimal_config(), FakeDetector(), client)
        with mock.patch.object(ddns.time, "sleep") as fake_sleep:
            self.assertTrue(updater.run_once())
        fake_sleep.assert_called_once_with(1.0)
        # 重试前重新查询发现记录已存在且内容一致：不再创建，也无需修改。
        self.assertEqual(client.created, [])
        self.assertEqual(client.edited, [])
        self.assertEqual(client.list_calls, 1)

    def test_warns_after_repeated_detection_failures(self):
        client = FakeCloudflareClient()
        detector = FakeDetector(error=ddns.DetectionError("offline"))
        updater = ddns.DDNSUpdater(minimal_config(), detector, client)
        with self.assertLogs("cloudflare-ddns", level="WARNING") as logs:
            for _ in range(ddns.STALE_RECORD_WARNING_THRESHOLD):
                updater.run_once()
        self.assertTrue(any("已连续" in line for line in logs.output))


class SingleInstanceLockTests(unittest.TestCase):
    def test_second_instance_is_rejected(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        config = Path(directory.name) / "config.json"
        config.write_text("{}", encoding="utf-8")
        first = ddns.SingleInstanceLock(config)
        second = ddns.SingleInstanceLock(config)
        self.addCleanup(first.release)
        self.addCleanup(second.release)
        self.assertTrue(first.acquire())
        self.assertFalse(second.acquire())
        first.release()
        self.assertTrue(second.acquire())


if __name__ == "__main__":
    unittest.main()
