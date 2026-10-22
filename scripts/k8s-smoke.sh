#!/usr/bin/env bash
# End-to-end check of a deployed stack (CI runs it against kind):
# tenant → sync → analysis → four-eyes plan → apply against the estate → findings resolved →
# AI-agent decision → load test → rolling restart under load with zero failed requests.
set -euo pipefail
API=${API:-http://localhost:30080}
NS=${NS:-irg}
IRG=${IRG:-bin/irg}

j() { curl -sS --fail-with-body -H "Authorization: Bearer $1" -H 'Content-Type: application/json' "${@:2}"; }

read -r TENANT ADMIN < <(kubectl -n "$NS" exec deploy/api -- /irg tenant create "ci-$RANDOM" Acme acme.example | jq -r '"\(.tenant_id) \(.admin_key)"')
echo "tenant $TENANT"
j "$ADMIN" -X POST "$API/v1/sync" | jq -c .
for i in $(seq 1 60); do
  if j "$ADMIN" "$API/v1/posture" >/tmp/posture.json 2>/dev/null; then break; fi
  sleep 2
done
jq '.current | {actors, identities_at_risk, open_by_severity, mean_identity_risk}' /tmp/posture.json
open=$(jq '[.current.open_by_severity[]] | add' /tmp/posture.json)
[ "$open" -gt 50 ] || { echo "expected findings, got $open"; exit 1; }

ANALYST=$(j "$ADMIN" -X POST "$API/v1/keys" -d '{"name":"ci-analyst","role":"analyst"}' | jq -r .key)
ids=$(j "$ANALYST" "$API/v1/findings?rule=offboarding_gap&limit=10" | jq -c '[.findings[].id]')
plan=$(j "$ANALYST" -X POST "$API/v1/plans" -d "{\"finding_ids\":$ids}")
pid=$(jq -r .id <<<"$plan")
echo "plan $pid resolves $(jq '.impact.resolves | length' <<<"$plan") findings"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $ANALYST" "$API/v1/plans/$pid/approve")
[ "$code" = 403 ] || { echo "analyst approved a plan (HTTP $code)"; exit 1; }
j "$ADMIN" -X POST "$API/v1/plans/$pid/approve" >/dev/null
j "$ADMIN" -X POST "$API/v1/plans/$pid/apply" >/dev/null
for i in $(seq 1 60); do
  st=$(j "$ADMIN" "$API/v1/plans/$pid" | jq -r .status)
  [ "$st" = applied ] && break
  [ "$st" = failed ] && { j "$ADMIN" "$API/v1/plans/$pid" | jq .; exit 1; }
  sleep 2
done
echo "plan $st"
for i in $(seq 1 60); do
  resolved=$(j "$ADMIN" "$API/v1/findings?status=resolved&rule=offboarding_gap" | jq .count)
  [ "$resolved" -ge "$(jq length <<<"$ids")" ] && break
  sleep 2
done
echo "resolved after re-sync: $resolved"
[ "$resolved" -ge "$(jq length <<<"$ids")" ] || exit 1
j "$ADMIN" "$API/v1/audit/verify" | jq -e '.intact == true' >/dev/null

echo '{}' > /tmp/agent-keys.json
for a in $(j "$ADMIN" "$API/v1/identities?kind=ai_agent&limit=1000" | jq -r '.identities[] | select(.owned and .status=="active") | .id' | head -8); do
  k=$(j "$ADMIN" -X POST "$API/v1/keys" -d "{\"name\":\"$a\",\"role\":\"agent\"}" | jq -r .key)
  jq --arg a "$a" --arg k "$k" '. + {($a): $k}' /tmp/agent-keys.json > /tmp/agent-keys.tmp && mv /tmp/agent-keys.tmp /tmp/agent-keys.json
done
a=$(jq -r 'keys[0]' /tmp/agent-keys.json)
k=$(jq -r --arg a "$a" '.[$a]' /tmp/agent-keys.json)
j "$k" -X POST "$API/v1/agents/decide" -d "{\"agent_id\":\"$a\",\"action\":\"s3:GetObject\",\"resource\":\"arn:aws:s3:::analytics-raw/x\"}" | jq -e '.decision == "allow"'

# rolling restart of the API while agents keep asking: no request may fail
"$IRG" loadtest -base "$API" -keys /tmp/agent-keys.json -c 8 -d 45s -out loadtest-k8s.json &
lt=$!
sleep 8
kubectl -n "$NS" rollout restart deployment/api
kubectl -n "$NS" rollout status deployment/api --timeout=180s
wait $lt
jq '{requests, errors, requests_per_second, latency_ms}' loadtest-k8s.json
jq -e '.errors == 0 and .requests > 1000' loadtest-k8s.json >/dev/null || { echo "requests failed during the rollout"; exit 1; }
echo "k8s smoke test passed"
