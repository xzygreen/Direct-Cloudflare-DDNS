#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
PROJECT_DIR="${SCRIPT_DIR:h}"
VERSION="$(<"${PROJECT_DIR}/VERSION")"
ZIP_PATH="${1:-${PROJECT_DIR}/build/DirectCloudflareDDNS-macOS-universal2.zip}"
DOWNLOAD_URL="${2:-}"
NOTES="${3:-Cloudflare DDNS ${VERSION}}"
OUTPUT_PATH="${4:-${PROJECT_DIR}/build/update-manifest.json}"

if [[ ! -f "${ZIP_PATH}" ]]; then
    print -u2 "找不到发布包：${ZIP_PATH}"
    exit 1
fi
if [[ -z "${DOWNLOAD_URL}" ]]; then
    print -u2 "用法：$0 [zip路径] <下载URL> [更新说明] [输出路径]"
    exit 2
fi

SHA256="$(/usr/bin/shasum -a 256 "${ZIP_PATH}" | /usr/bin/awk '{print $1}')"
/usr/bin/python3 -c '
import json, sys
version, url, sha256, notes, output = sys.argv[1:]
with open(output, "w", encoding="utf-8") as handle:
    json.dump(
        {"version": version, "url": url, "sha256": sha256, "notes": notes},
        handle,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    handle.write("\n")
' "${VERSION}" "${DOWNLOAD_URL}" "${SHA256}" "${NOTES}" "${OUTPUT_PATH}"

print "更新清单：${OUTPUT_PATH}"
