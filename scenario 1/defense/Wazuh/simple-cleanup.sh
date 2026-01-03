#!/bin/bash
LOG_FILE="/var/ossec/logs/active-responses.log"
LOCK_FILE="/var/lock/simple-cleanup.lock"
LOCK_FD=201

JQ_BIN=$(command -v jq || echo "/usr/bin/jq")
FIND_BIN=$(command -v find || echo "/usr/bin/find")
RM_BIN=$(command -v rm || echo "/usr/bin/rm")

log_wazuh() {
    local TIMESTAMP=$(LANG=C date '+%a %b %e %H:%M:%S %Z %Y')
    echo "$TIMESTAMP /var/ossec/$0 $COMMAND - $BADNAME $ALERT_ID" >> "$LOG_FILE"
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

if ! ip_is_local "$SRCIP" && ! ip_is_local "$DSTIP"; then
    exit 0
fi

exec {LOCK_FD}>"$LOCK_FILE"
flock -x "$LOCK_FD"

if [ "$COMMAND" = "add" ]; then
    BADNAME=$($JQ_BIN -r '.parameters.alert.data.msg | match("Known bad file name:\\s*(.*?)\\s+in command") | .captures[0].string // empty' 2>/dev/null <<<"$ALERT")
    
    if [ -n "$BADNAME" ] && [ "$BADNAME" != "empty" ]; then
        ACTION_PERFORMED=0
        
        FOUND_FILES=$($FIND_BIN /home/ftp /tmp /var/tmp -xdev -type f -name "$BADNAME" -maxdepth 5 2>/dev/null || true)
        
        for f in $FOUND_FILES; do
            if [ -e "$f" ]; then
                $RM_BIN -f "$f"
                ACTION_PERFORMED=1
            fi
        done
        
        if [ "$ACTION_PERFORMED" -eq 1 ]; then
            log_wazuh
        fi
    fi

elif [ "$COMMAND" = "delete" ]; then
    exit 0
fi

flock -u "$LOCK_FD"
exit 0
