#!/bin/sh
# Homebrew run-parts must return promptly. No boot hook is installed by default.
SCRIPT=$(readlink -f "$0") || exit 0
APP=$(dirname "$(dirname "$SCRIPT")")
[ -f "$APP/native/control.py" ] || exit 0
(
    attempt=0
    while [ "$attempt" -lt 15 ]; do
        if ip route get 1.1.1.1 >/dev/null 2>&1; then
            /usr/bin/python -B "$APP/native/control.py" boot > /tmp/flowseal-webos-boot.log 2>&1
            exit
        fi
        attempt=$((attempt + 1))
        sleep 3
    done
) </dev/null >/dev/null 2>&1 &
exit 0
