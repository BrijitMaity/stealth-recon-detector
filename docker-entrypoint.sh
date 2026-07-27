#!/bin/bash
# docker-entrypoint.sh

echo "[INFO] Starting SOC Engine Monitor in the background..."
python monitor.py &
MONITOR_PID=$!

echo "[INFO] Starting SOC Engine Dashboard in the foreground..."
python dashboard.py

# Wait for any process to exit
wait -n

# Exit with status of process that exited first
exit $?
