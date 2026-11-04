#!/bin/sh
# pg_dump into /backups (a host folder) when the container starts and every night at
# 03:00 UTC, keeping BACKUP_KEEP_DAYS days. Restore: see docs/DEPLOY.md. Copy this folder
# off the server too (rsync, restic, ...): a backup on the same disk is not a backup.
set -eu

dump() {
  file="/backups/corpsec-$(date -u +%Y%m%d-%H%M).dump"
  if pg_dump --format=custom --file="$file.partial"; then
    mv "$file.partial" "$file"
    echo "backup written: $file"
  else
    rm -f "$file.partial"
    echo "backup FAILED" >&2
  fi
  find /backups -name 'corpsec-*.dump' -mtime +"$BACKUP_KEEP_DAYS" -delete
}

dump
while true; do
  sleep 60
  if [ "$(date -u +%H%M)" = "0300" ]; then dump; fi
done
