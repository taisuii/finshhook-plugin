#!/bin/bash
# 用法: ./scripts/inject.sh <input.ipa> <hook.dylib>

IPA=$1
DYLIB=$2
WORK_DIR="work_$$"

if [ -z "$IPA" ] || [ -z "$DYLIB" ]; then
    echo "Usage: $0 <input.ipa> <hook.dylib>"
    exit 1
fi

echo "[*] 解包 IPA..."
mkdir -p "$WORK_DIR"
cp "$DYLIB" "$WORK_DIR/"
unzip -q "$IPA" -d "$WORK_DIR"

APP=$(find "$WORK_DIR/Payload" -name "*.app" -maxdepth 1 | head -1)
APP_BIN="$APP/$(basename "${APP%.app}")"
DYLIB_NAME=$(basename "$DYLIB")

echo "[*] 复制 dylib 到 App Bundle..."
cp "$DYLIB" "$APP/"

echo "[*] 写入 LC_LOAD_DYLIB..."
# 使用 insert_dylib（Actions 中通过 Homebrew 安装）
insert_dylib --strip-codesig --inplace \
    "@executable_path/$DYLIB_NAME" "$APP_BIN"

echo "[*] 重新打包 IPA..."
OUTPUT="hooked_$(basename $IPA)"
cd "$WORK_DIR" && zip -qr "../$OUTPUT" Payload/ && cd ..

echo "[*] 清理临时目录..."
rm -rf "$WORK_DIR"

echo "✅ 完成: $OUTPUT"