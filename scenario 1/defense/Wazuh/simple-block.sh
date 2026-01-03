#!/bin/bash
LOG_FILE="/var/ossec/logs/active-responses.log"
LOCK_FILE="/var/lock/simple-block.lock"
LOCK_FD=200

JQ_BIN=$(command -v jq || echo "/usr/bin/jq")
IPTABLES_BIN=$(command -v iptables || echo "/usr/sbin/iptables")

log_wazuh() {
    local TIMESTAMP=$(LANG=C date '+%a %b %e %H:%M:%S %Z %Y')
    echo "$TIMESTAMP /var/ossec/$0 $COMMAND - $BLOCK_IP $ALERT_ID" >> "$LOG_FILE"
}

ALERT=$(timeout 5 cat 2>/dev/null)
if [ -z "$ALERT" ]; then
    exit 1
fi

COMMAND=$($JQ_BIN -r '.command // empty' 2>/dev/null <<<"$ALERT")
ALERT_ID=$($JQ_BIN -r '.parameters.alert.id // "-" ' 2>/dev/null <<<"$ALERT")

SRCIP=$($JQ_BIN -r '.parameters.alert.data.src_ip // .parameters.alert.data.src // .parameters.alert.data.id.orig_h // empty' 2>/dev/null <<<"$ALERT")
DSTIP=$($JQ_BIN -r '.parameters.alert.data.dest_ip // .parameters.alert.data.dst // .parameters.alert.data.id.resp_h // empty' 2>/dev/null <<<"$ALERT")

if [ -z "$SRCIP" ] || [ -z "$DSTIP" ]; then
    exit 0
fi

LOCAL_IPS=$(ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
ip_is_local() {
    local ip="$1"
    for a in $LOCAL_IPS; do [ "$a" = "$ip" ] && return 0; done
    return 1
}

BLOCK_IP=""
if ip_is_local "$SRCIP"; then
    BLOCK_IP="$DSTIP"
elif ip_is_local "$DSTIP"; then
    BLOCK_IP="$SRCIP"
else
    exit 0
fi

if [ -z "$BLOCK_IP" ] || [ "$BLOCK_IP" == "empty" ]; then exit 0; fi

exec {LOCK_FD}>"$LOCK_FILE"
flock -x "$LOCK_FD"

if [ "$COMMAND" = "add" ]; then
    ACTION_PERFORMED=0
    
    if ! $IPTABLES_BIN -C INPUT -s "$BLOCK_IP" -j DROP 2>/dev/null; then
        $IPTABLES_BIN -I INPUT 1 -s "$BLOCK_IP" -j DROP
        ACTION_PERFORMED=1
    fi
    
    if ! $IPTABLES_BIN -C OUTPUT -d "$BLOCK_IP" -j DROP 2>/dev/null; then
        $IPTABLES_BIN -I OUTPUT 1 -d "$BLOCK_IP" -j DROP
        ACTION_PERFORMED=1
    fi
    
    if [ "$ACTION_PERFORMED" -eq 1 ]; then
        log_wazuh
    fi

elif [ "$COMMAND" = "delete" ]; then
    $IPTABLES_BIN -D INPUT -s "$BLOCK_IP" -j DROP 2>/dev/null || true
    $IPTABLES_BIN -D OUTPUT -d "$BLOCK_IP" -j DROP 2>/dev/null || true
    log_wazuh
fi

flock -u "$LOCK_FD"
exit 0
