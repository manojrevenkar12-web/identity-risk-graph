#!/usr/bin/env bash
# Run the whole platform locally against the synthetic estate, then load-test agent decisions.
#   DATABASE_URL=postgres://... scripts/demo.sh            (needs: go, curl, jq, a PostgreSQL)
# Prints the admin key and leaves the API on :8080 until you press Ctrl-C.
set -euo pipefail
cd "$(dirname "$0")/.."
export IRG_ESTATE_TOKEN=${IRG_ESTATE_TOKEN:-demo-estate-token} IRG_ADDR=${IRG_ADDR:-:8080} IRG_SYNC_INTERVAL=${IRG_SYNC_INTERVAL:-1h}
go build -o bin/irg ./cmd/irg
bin/irg estate -humans "${HUMANS:-2000}" -addr :9090 > estate.log 2>&1 &
pids=($!)
trap 'kill "${pids[@]}" 2>/dev/null' EXIT
bin/irg migrate
slug="demo-$RANDOM"
read -r tenant admin < <(bin/irg tenant create "$slug" "Acme" acme.example | jq -r '"\(.tenant_id) \(.admin_key)"')
bin/irg tenant set "$tenant" estate_url http://localhost:9090
bin/irg all > api.log 2>&1 &
pids+=($!)
api=http://localhost${IRG_ADDR}
until curl -sf "$api/readyz" >/dev/null; do sleep 0.3; done
H=(-H "Authorization: Bearer $admin" -H 'Content-Type: application/json')
job=$(curl -sf "${H[@]}" -X POST "$api/v1/sync" | jq -r .job_id)
until curl -sf "${H[@]}" "$api/v1/posture" >/dev/null; do sleep 0.5; done
echo "posture:"; curl -sf "${H[@]}" "$api/v1/posture" | jq '.current | {mean_identity_risk, identities_at_risk, actors, open_by_severity}'
# one key per owned, active agent
echo '{}' > agent-keys.json
for a in $(curl -sf "${H[@]}" "$api/v1/identities?kind=ai_agent&limit=1000" | jq -r '.identities[] | select(.owned and .status=="active") | .id' | head -32); do
  k=$(curl -sf "${H[@]}" -X POST "$api/v1/keys" -d "{\"name\":\"$a\",\"role\":\"agent\"}" | jq -r .key)
  jq --arg a "$a" --arg k "$k" '. + {($a): $k}' agent-keys.json > agent-keys.tmp && mv agent-keys.tmp agent-keys.json
done
bin/irg loadtest -base "$api" -keys agent-keys.json -c "${CONCURRENCY:-32}" -d "${DURATION:-20s}" -out "${LOADTEST_OUT:-loadtest.json}"
echo "admin key: $admin"
[ "${KEEP_RUNNING:-0}" = 1 ] && wait
