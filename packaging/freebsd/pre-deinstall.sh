#!/bin/sh
# Stop it before its files go; the settings, the state and the user stay
# for a reinstall (remove /usr/local/etc/connlog and /var/db/connlog by hand).
service connlog_agent onestop >/dev/null 2>&1 || true
exit 0
