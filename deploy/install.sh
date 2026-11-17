#!/bin/sh
# Hydra-Radar installer for Debian (run as root from the hydra-radar directory).
set -eu
DEST=/opt/hydra-radar
USER_NAME=hydra

apt-get update -qq
apt-get install -y -qq python3 python3-venv ca-certificates

id "$USER_NAME" >/dev/null 2>&1 || \
    useradd --system --home-dir "$DEST" --shell /usr/sbin/nologin "$USER_NAME"

mkdir -p "$DEST/data"
cp radar.py requirements.txt "$DEST/"
[ -f "$DEST/config.json" ] || cp config.json "$DEST/config.json"   # never overwrite a live config
chown -R "$USER_NAME:$USER_NAME" "$DEST"
chmod 600 "$DEST/config.json"

runuser -u "$USER_NAME" -- python3 -m venv "$DEST/venv"
runuser -u "$USER_NAME" -- "$DEST/venv/bin/pip" install -q --upgrade pip
runuser -u "$USER_NAME" -- "$DEST/venv/bin/pip" install -q -r "$DEST/requirements.txt"

[ -f /etc/cron.d/hydra-radar ] || install -m 644 deploy/hydra-radar.cron /etc/cron.d/hydra-radar

echo "Installed to $DEST."
echo "Next: edit $DEST/config.json (webhook URL), then test:"
echo "  sudo -u $USER_NAME $DEST/venv/bin/python $DEST/radar.py --test-webhook"
echo "  sudo -u $USER_NAME $DEST/venv/bin/python $DEST/radar.py --dry-run"
