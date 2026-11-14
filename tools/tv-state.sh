#!/bin/sh
printf '\n=== engine state ===\n'
cat /tmp/flowseal-webos/state.json /tmp/flowseal-webos/engine.json /tmp/flowseal-webos/supervisor.json 2>/dev/null
printf '\n=== service log ===\n'
tail -n 100 /tmp/flowseal-webos/service.log 2>/dev/null
printf '\n=== routes ===\n'
ip route show
