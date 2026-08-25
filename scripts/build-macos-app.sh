#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
PROJECT_DIR="${SCRIPT_DIR:h}"
BUILD_DIR="${PROJECT_DIR}/build"
APP_PATH="${BUILD_DIR}/DirectCloudflareDDNS.app"
BUILD_ARCHS_TEXT="${BUILD_ARCHS:-arm64 x86_64}"
BUILD_ARCH_LIST=(${=BUILD_ARCHS_TEXT})
for requested_arch in "${BUILD_ARCH_LIST[@]}"; do
    if [[ "${requested_arch}" != "arm64" && "${requested_arch}" != "x86_64" ]]; then
        print -u2 "不支持的构建架构：${requested_arch}"
        exit 2
    fi
done
if (( ${#BUILD_ARCH_LIST[@]} > 1 )); then
    ARCH_LABEL="universal2"
else
    ARCH_LABEL="${BUILD_ARCH_LIST[1]}"
fi
ZIP_PATH="${BUILD_DIR}/DirectCloudflareDDNS-macOS-${ARCH_LABEL}.zip"
CHECKSUM_PATH="${ZIP_PATH}.sha256"
CONTENTS_PATH="${APP_PATH}/Contents"
MODULE_CACHE="${BUILD_DIR}/ModuleCache"
ICON_DIR="${BUILD_DIR}/icon"
ICON_FILE="${ICON_DIR}/AppIcon.icns"
APP_EXECUTABLE="${CONTENTS_PATH}/MacOS/DirectCloudflareDDNS"
AGENT_EXECUTABLE="${CONTENTS_PATH}/Library/LaunchServices/DirectCloudflareDDNSAgent"
VERSION="$(<"${PROJECT_DIR}/VERSION")"
SIGNING_IDENTITY="${SIGNING_IDENTITY:--}"

if [[ -n "${DEVELOPER_DIR:-}" ]]; then
    : # Respect an explicitly selected toolchain.
elif [[ -d "/Applications/Xcode.app/Contents/Developer" ]]; then
    export DEVELOPER_DIR="/Applications/Xcode.app/Contents/Developer"
elif [[ -d "/Applications/Xcode-beta.app/Contents/Developer" ]]; then
    export DEVELOPER_DIR="/Applications/Xcode-beta.app/Contents/Developer"
fi

SWIFTC="$(/usr/bin/xcrun --find swiftc)"
MACOS_SDK="${MACOS_SDK_OVERRIDE:-$(/usr/bin/xcrun --sdk macosx --show-sdk-path)}"
TARGET_ARCH="$(/usr/bin/uname -m)"
export CLANG_MODULE_CACHE_PATH="${MODULE_CACHE}"
export SWIFT_MODULECACHE_PATH="${MODULE_CACHE}"

if [[ "${APP_PATH}" != "${PROJECT_DIR}/build/DirectCloudflareDDNS.app" ]]; then
    print -u2 "拒绝清理非预期构建路径：${APP_PATH}"
    exit 1
fi
if [[ "${ZIP_PATH}" != "${PROJECT_DIR}/build/DirectCloudflareDDNS-macOS-${ARCH_LABEL}.zip" ]]; then
    print -u2 "拒绝清理非预期压缩包路径：${ZIP_PATH}"
    exit 1
fi

/bin/rm -rf "${APP_PATH}"
/bin/rm -f "${ZIP_PATH}"
/bin/rm -f "${CHECKSUM_PATH}"
/bin/rm -rf "${MODULE_CACHE}"
/bin/mkdir -p \
    "${CONTENTS_PATH}/MacOS" \
    "${CONTENTS_PATH}/Resources" \
    "${CONTENTS_PATH}/Library/LaunchAgents" \
    "${CONTENTS_PATH}/Library/LaunchServices" \
    "${MODULE_CACHE}" \
    "${ICON_DIR}"

# The app icon is rendered from source so the artwork stays reviewable in git.
"${SWIFTC}" \
    -O \
    -sdk "${MACOS_SDK}" \
    -target "${TARGET_ARCH}-apple-macosx13.0" \
    -module-cache-path "${MODULE_CACHE}" \
    "${PROJECT_DIR}/scripts/make-icon.swift" \
    -framework AppKit \
    -framework ImageIO \
    -o "${ICON_DIR}/make-icon"
"${ICON_DIR}/make-icon" "${ICON_FILE}"

build_architecture() {
    local arch="$1"
    local arch_cache="${MODULE_CACHE}/${arch}"
    /bin/rm -rf "${arch_cache}"
    /bin/mkdir -p "${arch_cache}"
    "${SWIFTC}" \
        -swift-version 5 \
        -strict-concurrency=minimal \
        -parse-as-library \
        -O \
        -sdk "${MACOS_SDK}" \
        -target "${arch}-apple-macosx13.0" \
        -module-cache-path "${arch_cache}" \
        "${PROJECT_DIR}/macos/CoreUtilities.swift" \
        "${PROJECT_DIR}/macos/DirectCloudflareDDNSApp.swift" \
        -framework AppKit \
        -framework Network \
        -framework Security \
        -framework ServiceManagement \
        -framework SwiftUI \
        -framework UserNotifications \
        -o "${BUILD_DIR}/DirectCloudflareDDNS-${arch}"
    "${SWIFTC}" \
        -swift-version 5 \
        -strict-concurrency=minimal \
        -O \
        -sdk "${MACOS_SDK}" \
        -target "${arch}-apple-macosx13.0" \
        -module-cache-path "${arch_cache}" \
        "${PROJECT_DIR}/macos/DirectCloudflareDDNSAgent.swift" \
        -framework LocalAuthentication \
        -framework Security \
        -o "${BUILD_DIR}/DirectCloudflareDDNSAgent-${arch}"
}

app_slices=()
agent_slices=()
for arch in "${BUILD_ARCH_LIST[@]}"; do
    print "正在构建 ${arch}…"
    build_architecture "${arch}"
    app_slices+=("${BUILD_DIR}/DirectCloudflareDDNS-${arch}")
    agent_slices+=("${BUILD_DIR}/DirectCloudflareDDNSAgent-${arch}")
    print "${arch} 构建完成"
done

if (( ${#BUILD_ARCH_LIST[@]} > 1 )); then
    /usr/bin/lipo -create "${app_slices[@]}" -output "${APP_EXECUTABLE}"
    /usr/bin/lipo -create "${agent_slices[@]}" -output "${AGENT_EXECUTABLE}"
else
    /bin/cp "${app_slices[1]}" "${APP_EXECUTABLE}"
    /bin/cp "${agent_slices[1]}" "${AGENT_EXECUTABLE}"
fi
/bin/chmod 755 "${APP_EXECUTABLE}" "${AGENT_EXECUTABLE}"

/usr/bin/install -m 644 "${PROJECT_DIR}/macos/Info.plist" "${CONTENTS_PATH}/Info.plist"
/usr/bin/install -m 644 "${ICON_FILE}" "${CONTENTS_PATH}/Resources/AppIcon.icns"
/usr/bin/install -m 644 "${PROJECT_DIR}/cloudflare_ddns.py" "${CONTENTS_PATH}/Resources/cloudflare_ddns.py"
/usr/bin/install -m 644 "${PROJECT_DIR}/VERSION" "${CONTENTS_PATH}/Resources/VERSION"
/usr/bin/install -m 644 \
    "${PROJECT_DIR}/macos/io.github.xzygreen.direct-cloudflare-ddns.agent.plist" \
    "${CONTENTS_PATH}/Library/LaunchAgents/io.github.xzygreen.direct-cloudflare-ddns.agent.plist"

required_files=(
    "${CONTENTS_PATH}/Info.plist"
    "${CONTENTS_PATH}/Resources/AppIcon.icns"
    "${CONTENTS_PATH}/Resources/cloudflare_ddns.py"
    "${CONTENTS_PATH}/Library/LaunchAgents/io.github.xzygreen.direct-cloudflare-ddns.agent.plist"
)
for required_file in "${required_files[@]}"; do
    if [[ ! -f "${required_file}" ]]; then
        print -u2 "App 包缺少必需文件：${required_file}"
        exit 1
    fi
done
if [[ ! -x "${APP_EXECUTABLE}" || ! -x "${AGENT_EXECUTABLE}" ]]; then
    print -u2 "App 包缺少可执行文件"
    exit 1
fi

# A production build can be fully self-contained by pointing this at a relocatable
# universal Python 3.9+ prefix (for example python-build-standalone output).
if [[ -n "${EMBEDDED_PYTHON_PREFIX:-}" ]]; then
    if [[ ! -x "${EMBEDDED_PYTHON_PREFIX}/bin/python3" ]]; then
        print -u2 "EMBEDDED_PYTHON_PREFIX 中找不到 bin/python3"
        exit 1
    fi
    /usr/bin/ditto "${EMBEDDED_PYTHON_PREFIX}" "${CONTENTS_PATH}/Resources/python"
fi

/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString ${VERSION}" "${CONTENTS_PATH}/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion ${VERSION//./}" "${CONTENTS_PATH}/Info.plist"
if [[ -n "${UPDATE_FEED_URL:-}" ]]; then
    /usr/libexec/PlistBuddy -c "Add :DirectDDNSUpdateFeedURL string ${UPDATE_FEED_URL}" \
        "${CONTENTS_PATH}/Info.plist"
fi
/usr/bin/plutil -lint "${CONTENTS_PATH}/Info.plist"

codesign_options=(--force --deep --sign "${SIGNING_IDENTITY}")
if [[ "${SIGNING_IDENTITY}" != "-" ]]; then
    codesign_options+=(--options runtime --timestamp)
fi
/usr/bin/codesign "${codesign_options[@]}" "${APP_PATH}"
/usr/bin/codesign --verify --deep --strict "${APP_PATH}"
/usr/bin/ditto -c -k --sequesterRsrc --keepParent "${APP_PATH}" "${ZIP_PATH}"
/usr/bin/shasum -a 256 "${ZIP_PATH}" > "${CHECKSUM_PATH}"

if [[ -n "${NOTARY_PROFILE:-}" && "${SIGNING_IDENTITY}" != "-" ]]; then
    /usr/bin/xcrun notarytool submit "${ZIP_PATH}" --keychain-profile "${NOTARY_PROFILE}" --wait
    /usr/bin/xcrun stapler staple "${APP_PATH}"
    /usr/bin/ditto -c -k --sequesterRsrc --keepParent "${APP_PATH}" "${ZIP_PATH}"
    /usr/bin/shasum -a 256 "${ZIP_PATH}" > "${CHECKSUM_PATH}"
fi

print "构建完成：${APP_PATH}"
print "分发包：${ZIP_PATH}"
print "校验值：${CHECKSUM_PATH}"
