#!/bin/sh
# docker-entrypoint.sh — Runs the relay and restarts it when TLS certificates
# change on disk.  Designed for short-lived certs (e.g. Let's Encrypt, 10-day
# rotation) mounted into the container as a volume.
#
# The script polls cert file modification times every CERT_POLL_INTERVAL seconds
# (default 60).  When a change is detected the relay process receives SIGTERM,
# and after a brief grace period it is restarted with the fresh certs.

set -e

CERT_POLL_INTERVAL="${CERT_POLL_INTERVAL:-60}"

# ── helpers ─────────────────────────────────────────────────────
cert_mtime() {
    # Return combined mtime of cert + key (empty string if files don't exist)
    local mtime=""
    if [ -n "$RELAY_CERT_PEM" ] && [ -f "$RELAY_CERT_PEM" ]; then
        mtime="$(stat -c %Y "$RELAY_CERT_PEM" 2>/dev/null || stat -f %m "$RELAY_CERT_PEM" 2>/dev/null)"
    fi
    if [ -n "$RELAY_KEY_PEM" ] && [ -f "$RELAY_KEY_PEM" ]; then
        mtime="${mtime}:$(stat -c %Y "$RELAY_KEY_PEM" 2>/dev/null || stat -f %m "$RELAY_KEY_PEM" 2>/dev/null)"
    fi
    echo "$mtime"
}

# ── main loop ───────────────────────────────────────────────────
while true; do
    LAST_MTIME="$(cert_mtime)"

    echo "[entrypoint] Starting relay (PID will follow)..."
    relay "$@" &
    RELAY_PID=$!
    echo "[entrypoint] Relay started (PID $RELAY_PID)"

    # If no cert files are configured, just wait for the process (no watching)
    if [ -z "$RELAY_CERT_PEM" ] || [ -z "$RELAY_KEY_PEM" ]; then
        echo "[entrypoint] No cert files configured — running in self-signed/dev mode"
        echo "[entrypoint] Cert watching disabled (set RELAY_CERT_PEM and RELAY_KEY_PEM for production)"
        wait $RELAY_PID
        exit $?
    fi

    # Log certificate expiry for operational visibility
    if [ -f "$RELAY_CERT_PEM" ]; then
        EXPIRY=$(openssl x509 -in "$RELAY_CERT_PEM" -noout -enddate 2>/dev/null | cut -d= -f2)
        if [ -n "$EXPIRY" ]; then
            echo "[entrypoint] Certificate expires: $EXPIRY"
        fi
    fi

    echo "[entrypoint] Watching certs (poll every ${CERT_POLL_INTERVAL}s): $RELAY_CERT_PEM, $RELAY_KEY_PEM"

    # Poll for cert changes while the relay is running
    while kill -0 $RELAY_PID 2>/dev/null; do
        sleep "$CERT_POLL_INTERVAL"

        CURRENT_MTIME="$(cert_mtime)"
        if [ "$CURRENT_MTIME" != "$LAST_MTIME" ]; then
            echo "[entrypoint] Certificate change detected — restarting relay..."
            kill -TERM $RELAY_PID 2>/dev/null || true
            # Grace period for in-flight connections to drain
            sleep 2
            kill -KILL $RELAY_PID 2>/dev/null || true
            wait $RELAY_PID 2>/dev/null || true
            break
        fi
    done

    # If the relay exited on its own (not from cert rotation), propagate exit
    if ! kill -0 $RELAY_PID 2>/dev/null; then
        wait $RELAY_PID
        EXIT_CODE=$?
        if [ "$CURRENT_MTIME" = "$LAST_MTIME" ]; then
            echo "[entrypoint] Relay exited with code $EXIT_CODE"
            exit $EXIT_CODE
        fi
    fi

    echo "[entrypoint] Restarting with new certificates..."
done
