#!/usr/bin/env bash
# roscaelumの結合テスト。実際のnftablesにルールを適用し、パケットの
# 許可・拒否が意図通りに機能するかを検証する。
#
# テストは独立したネットワーク名前空間(netns)内で行う。netfilterの
# ルールはnetnsごとに独立しているため、ホスト側のファイアウォールには
# 一切触れない。
#
# 実行にはroot権限(CAP_NET_ADMIN/CAP_SYS_ADMIN)が必要:
#   sudo bash scripts/integration-test.sh

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
	echo "This script must be run as root." >&2
	exit 1
fi

BIN="$(pwd)/rcfctl"
CLIENT_NS="rosca-client"
SERVER_NS="rosca-server"
CONFIG="/tmp/roscaelum-integration.yml"

if [ ! -x "$BIN" ]; then
	echo "rcfctl binary not found at $BIN. Run 'go build -o rcfctl main.go' first." >&2
	exit 1
fi

cleanup() {
	kill $(jobs -p) 2>/dev/null || true
	ip netns del "$CLIENT_NS" 2>/dev/null || true
	ip netns del "$SERVER_NS" 2>/dev/null || true
	rm -f "$CONFIG"
}
trap cleanup EXIT

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

# サーバー側nsからクライアント側nsのIPへTCP接続できるか試す
can_connect() {
	ip netns exec "$CLIENT_NS" timeout 5 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null
}

# テスト用設定: TCP 8080のみ10.0.0.0/24からの接続を許可する
write_config() {
	cat > "$CONFIG" <<'EOF'
default:
  allowAllIn: false
  allowAllOut: false
  allowAllFwd: false
  allowPing: true
  enableIPv6: false
  enableLogging: false

ports:
  - port: 8080
    proto: "tcp"
    allowIP: "10.0.0.0/24"
EOF
}

echo "==> Setting up network namespaces"
cleanup
ip netns add "$CLIENT_NS"
ip netns add "$SERVER_NS"

ip link add veth-srv type veth peer name veth-cli
ip link set veth-srv netns "$SERVER_NS"
ip link set veth-cli netns "$CLIENT_NS"

ip -n "$SERVER_NS" addr add 10.0.0.1/24 dev veth-srv
ip -n "$SERVER_NS" link set veth-srv up
ip -n "$SERVER_NS" link set lo up
ip -n "$CLIENT_NS" addr add 10.0.0.2/24 dev veth-cli
ip -n "$CLIENT_NS" link set veth-cli up
ip -n "$CLIENT_NS" link set lo up

echo "==> Starting listeners on ports 8080 (allowed) and 8081 (denied)"
ip netns exec "$SERVER_NS" nc -lk 8080 >/dev/null 2>&1 &
ip netns exec "$SERVER_NS" nc -lk 8081 >/dev/null 2>&1 &
sleep 1

echo "==> Baseline: both ports are reachable without a firewall"
can_connect 10.0.0.1 8080 || fail "port 8080 is unreachable before enabling the firewall"
can_connect 10.0.0.1 8081 || fail "port 8081 is unreachable before enabling the firewall"

echo "==> Enabling firewall in $SERVER_NS"
write_config
ip netns exec "$SERVER_NS" "$BIN" -f "$CONFIG" enable

echo "==> Verifying the ruleset was actually loaded"
RULESET="$(ip netns exec "$SERVER_NS" nft list table inet roscaelum)"
echo "$RULESET"
echo "$RULESET" | grep -q 'table inet roscaelum' || fail "table inet roscaelum not found"
for chain in input output forward syn-flood; do
	echo "$RULESET" | grep -q "chain $chain" || fail "chain $chain not found"
done
echo "$RULESET" | grep -q 'tcp dport 8080' || fail "allow rule for port 8080 not found"
echo "$RULESET" | grep -q '10.0.0.0/24' || fail "source restriction for port 8080 not found"
echo "$RULESET" | grep -q 'policy drop' || fail "input chain policy is not drop"

echo "==> Allowed port is still reachable"
can_connect 10.0.0.1 8080 || fail "allowed port 8080 was blocked"

echo "==> Unlisted port is blocked"
if can_connect 10.0.0.1 8081; then
	fail "denied port 8081 was reachable"
fi

echo "==> enable/apply are idempotent"
ip netns exec "$SERVER_NS" "$BIN" -f "$CONFIG" enable
ip netns exec "$SERVER_NS" "$BIN" -f "$CONFIG" apply
ip netns exec "$SERVER_NS" nft list table inet roscaelum >/dev/null ||
	fail "table disappeared after re-applying"

echo "==> disable removes the firewall"
ip netns exec "$SERVER_NS" "$BIN" disable
if ip netns exec "$SERVER_NS" nft list table inet roscaelum >/dev/null 2>&1; then
	fail "table still exists after disable"
fi

echo "==> Previously blocked port is reachable after disable"
can_connect 10.0.0.1 8081 || fail "port 8081 should be reachable after disable"

echo "==> All integration tests passed"
