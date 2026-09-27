#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v swift >/dev/null || ! swift --version | grep -Eq '^Swift version 6\.4(\.0)? \('; then
  if [[ "$(uname -s)" != Linux ]]; then
    echo 'Install Swift 6.4.0 before building DocC.' >&2
    exit 1
  fi

  export SWIFTLY_HOME_DIR="$PWD/.build/blahdiem-swiftly"
  export SWIFTLY_BIN_DIR="$PWD/.build/blahdiem-swiftly-bin"
  if [[ ! -x "$SWIFTLY_BIN_DIR/swiftly" ]] || [[ "$("$SWIFTLY_BIN_DIR/swiftly" --version 2>/dev/null)" != 1.2.0 ]]; then
    temporary_directory="$(mktemp -d)"
    trap 'rm -rf "$temporary_directory"' EXIT
    architecture="$(uname -m)"
    swiftly_archive="swiftly-1.2.0-${architecture}.tar.gz"
    swiftly_url="https://download.swift.org/swiftly/linux/${swiftly_archive}"
    curl --fail --location --retry 3 --output "$temporary_directory/$swiftly_archive" "$swiftly_url"
    curl --fail --location --retry 3 --output "$temporary_directory/$swiftly_archive.sig" "$swiftly_url.sig"
    mkdir -m 700 "$temporary_directory/gnupg"
    export GNUPGHOME="$temporary_directory/gnupg"
    curl --compressed --fail --location --retry 3 https://www.swift.org/keys/all-keys.asc | gpg --batch --import
    gpg --batch --verify "$temporary_directory/$swiftly_archive.sig" "$temporary_directory/$swiftly_archive"
    unset GNUPGHOME
    tar -xzf "$temporary_directory/$swiftly_archive" -C "$temporary_directory"
    "$temporary_directory/swiftly" init --no-modify-profile --skip-install --quiet-shell-followup --assume-yes
    rm -rf "$temporary_directory"
    trap - EXIT
  fi

  # Swiftly can report a missing optional system package after installing the
  # toolchain, so verify the selected compiler below regardless of its status.
  "$SWIFTLY_BIN_DIR/swiftly" install 6.4.0 --use --assume-yes || true
  # Swiftly writes PATH and toolchain locations here during init.
  source "$SWIFTLY_HOME_DIR/env.sh"
fi

swift --version
if ! swift --version | grep -Eq '^Swift version 6\.4(\.0)? \('; then
  echo 'Swift 6.4.0 is required to build the DocC site.' >&2
  exit 1
fi
rm -rf dist
mkdir -p dist/blahdiem
swift package \
  --allow-writing-to-directory ./dist/blahdiem \
  generate-documentation \
  --target BlahDiem \
  --output-path ./dist/blahdiem \
  --transform-for-static-hosting \
  --hosting-base-path blahdiem

test -f dist/blahdiem/documentation/blahdiem/index.html
test -f dist/blahdiem/data/documentation/blahdiem.json

cat > dist/blahdiem/index.html <<'EOF'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="0; url=/blahdiem/documentation/blahdiem/">
  <title>BlahDiem documentation</title>
</head>
<body>
  <a href="/blahdiem/documentation/blahdiem/">BlahDiem documentation</a>
</body>
</html>
EOF
