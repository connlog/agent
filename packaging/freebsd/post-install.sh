#!/bin/sh
# The agent's own user, and the directories only it and root read.
if ! pw groupshow connlog >/dev/null 2>&1; then
	pw groupadd connlog
fi
if ! pw usershow connlog >/dev/null 2>&1; then
	pw useradd connlog -g connlog -d /nonexistent -s /usr/sbin/nologin -c "ConnLog agent"
fi
install -d -o root -g connlog -m 0750 /usr/local/etc/connlog
install -d -o root -g connlog -m 0750 /usr/local/etc/connlog/integrations.d
install -d -o connlog -g connlog -m 0700 /var/db/connlog
if [ -f /usr/local/etc/connlog/agent.conf ]; then
	chown root:connlog /usr/local/etc/connlog/agent.conf
	chmod 0640 /usr/local/etc/connlog/agent.conf
fi
exit 0
