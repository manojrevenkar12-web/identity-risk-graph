#!/usr/bin/env bash
# On a failed kind deploy, publish cluster state as GitHub annotations so it is readable from the
# run summary without downloading logs.
set -u
emit() { # title, text
  local body
  body=$(printf '%s' "$2" | tail -c 6000 | sed -e 's/%/%25/g' -e 's/\r/%0D/g' | awk 'BEGIN{ORS="%0A"} {print}')
  echo "::error title=$1::$body"
}
[ -f smoke.log ] && emit "smoke test output" "$(tail -n 50 smoke.log)"
emit "pods" "$(kubectl -n irg get pods -o wide 2>&1)"
emit "events" "$(kubectl -n irg get events --sort-by=.lastTimestamp 2>&1 | grep -v Normal | tail -n 40)"
for p in $(kubectl -n irg get pods -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}'); do
  ready=$(kubectl -n irg get pod "$p" -o jsonpath='{.status.containerStatuses[0].ready}')
  [ "$ready" = "true" ] && continue
  emit "not ready $p" "$(kubectl -n irg describe pod "$p" 2>&1 | sed -n '/^Containers:/,/^Conditions:/p' | head -n 40)
--- logs ---
$(kubectl -n irg logs "$p" --tail=40 2>&1)
--- previous ---
$(kubectl -n irg logs "$p" --previous --tail=20 2>&1)"
done
