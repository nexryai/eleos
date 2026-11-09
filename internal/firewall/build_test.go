package firewall

import (
	"bytes"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"eleos/internal/config"
)

func testConfig() *config.Config {
	return &config.Config{
		Default: config.DefaultConfig{
			AllowAllIn:    false,
			AllowAllOut:   false,
			AllowAllFwd:   false,
			AllowPing:     true,
			EnableIPv6:    true,
			EnableLogging: true,
		},
		IpSet: []config.IpSetConfig{
			{Name: "TRUSTED", Ip: []string{"0.0.0.0", "127.0.0.1"}},
		},
		Security: config.SecurityConfig{
			AlwaysDenyIP: []string{"1.1.1.1"},
		},
		Ports: []config.PortConfig{
			{Port: 22, Proto: "tcp", AllowIP: "$TRUSTED"},
			{Port: 80},
		},
		Outgoing: config.OutgoingConfig{
			Allowed: []config.OutgoingAllowConfig{
				{Dport: "53", Proto: "udp"},
			},
		},
	}
}

func rulesByChain(rs *Ruleset, name string) []*nftables.Rule {
	var rules []*nftables.Rule
	for _, r := range rs.Rules {
		if r.Chain.Name == name {
			rules = append(rules, r)
		}
	}
	return rules
}

func chainByName(rs *Ruleset, name string) *nftables.Chain {
	for _, c := range rs.Chains {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestBuildBasic(t *testing.T) {
	rs, err := Build(testConfig())
	if err != nil {
		t.Fatalf("Build returned an error: %v", err)
	}

	if rs.Table.Name != TableName || rs.Table.Family != nftables.TableFamilyINet {
		t.Errorf("unexpected table: %+v", rs.Table)
	}

	// ルーター/NAT未構成なのでNATチェーンは作成されない
	if len(rs.Chains) != 4 {
		t.Errorf("expected 4 chains, got %d", len(rs.Chains))
	}
	if chainByName(rs, "postrouting") != nil || chainByName(rs, "prerouting") != nil {
		t.Error("NAT chains must not be created without router/NAT config")
	}

	input := chainByName(rs, "input")
	if input == nil {
		t.Fatal("input chain not found")
	}
	if *input.Policy != nftables.ChainPolicyDrop {
		t.Error("input chain policy must be drop")
	}
	if *input.Hooknum != *nftables.ChainHookInput || *input.Priority != *nftables.ChainPriorityFilter {
		t.Error("input chain has wrong hook or priority")
	}

	// ルール数の内訳:
	// ct established,related / ct invalid / lo / non-syn new = 4
	// XMAS / NULL / MSS = 3
	// IPフラグメント = 1
	// alwaysDenyIP = 1
	// ping (v4/v6それぞれaccept+drop) = 4
	// IPv6近隣探索 = 3
	// syn-floodジャンプ = 1
	// ポート22 ($TRUSTEDの2要素に展開) = 2
	// ポート80 (tcp+udp) = 2
	// ロギング = 1
	expected := 22
	if got := len(rulesByChain(rs, "input")); got != expected {
		t.Errorf("expected %d input rules, got %d", expected, got)
	}

	// $TRUSTEDが要素ごとに展開されているか確認
	// ポート22の許可ルールは [l4proto, dport, saddr, verdict] で9式
	trustedAddrs := [][]byte{}
	for _, r := range rulesByChain(rs, "input") {
		if len(r.Exprs) != 9 {
			continue
		}
		dportCmp, ok := r.Exprs[3].(*expr.Cmp)
		if !ok || !bytes.Equal(dportCmp.Data, []byte{0, 22}) {
			continue
		}
		saddrCmp, ok := r.Exprs[7].(*expr.Cmp)
		if !ok {
			continue
		}
		trustedAddrs = append(trustedAddrs, saddrCmp.Data)
	}
	if len(trustedAddrs) != 2 {
		t.Fatalf("expected 2 rules expanded from $TRUSTED, got %d", len(trustedAddrs))
	}
	if !bytes.Equal(trustedAddrs[0], []byte{0, 0, 0, 0}) || !bytes.Equal(trustedAddrs[1], []byte{127, 0, 0, 1}) {
		t.Errorf("unexpected saddr values: %v", trustedAddrs)
	}

	// syn-floodチェーンはrate limit + ログドロップの2ルール
	synFlood := rulesByChain(rs, "syn-flood")
	if len(synFlood) != 2 {
		t.Fatalf("expected 2 syn-flood rules, got %d", len(synFlood))
	}
	limit, ok := synFlood[0].Exprs[0].(*expr.Limit)
	if !ok {
		t.Fatal("first syn-flood expr must be a limit")
	}
	if limit.Rate != 30 || limit.Burst != 60 || limit.Unit != expr.LimitTimeSecond {
		t.Errorf("unexpected limit: %+v", limit)
	}

	// outputチェーン: lo / icmp / localhost / icmpv6 11種 / 53 udp / non-syn / ログ = 17
	expectedOutput := 17
	if got := len(rulesByChain(rs, "output")); got != expectedOutput {
		t.Errorf("expected %d output rules, got %d", expectedOutput, got)
	}
}

func TestBuildDisableProtections(t *testing.T) {
	cfg := testConfig()
	cfg.Security.DisablePortScanProtection = true
	cfg.Security.DisableIpFragmentsBlock = true
	cfg.Default.AllowPing = false
	cfg.Default.EnableIPv6 = false
	cfg.Default.EnableLogging = false

	rs, err := Build(cfg)
	if err != nil {
		t.Fatalf("Build returned an error: %v", err)
	}

	// 22 - 3(ポートスキャン) - 1(フラグメント) - 4(ping) - 3(近隣探索) - 1(ログ) = 10
	expected := 10
	if got := len(rulesByChain(rs, "input")); got != expected {
		t.Errorf("expected %d input rules, got %d", expected, got)
	}
}

func TestBuildRouterAndNat(t *testing.T) {
	cfg := testConfig()
	cfg.Router = config.RouterConfig{
		ConfigAsRouter:          true,
		WANInterface:            "eth0",
		PrivateNetworkAddresses: []string{"192.168.10.0/24", "192.168.20.0/24"},
		LANInterfaces:           []string{"eth1"},
		ForceDNS:                "192.168.0.1",
		CustomRoutes: []config.CustomRoutesConfig{
			{AllowIP: "10.0.10.0/24", AllowInterface: "wg1", AllowDST: "192.168.10.0/24"},
		},
	}
	cfg.Nat = []config.NatConfig{
		{Interface: "wg0", AllowIP: "10.0.0.0/24", DstIP: "10.0.0.1", DstPort: "53", Proto: "udp", NatTo: "192.168.1.100:53"},
	}

	rs, err := Build(cfg)
	if err != nil {
		t.Fatalf("Build returned an error: %v", err)
	}

	if len(rs.Chains) != 6 {
		t.Errorf("expected 6 chains, got %d", len(rs.Chains))
	}

	// ルーター構成時のpreroutingはpriority 100
	prerouting := chainByName(rs, "prerouting")
	if prerouting == nil {
		t.Fatal("prerouting chain not found")
	}
	if *prerouting.Priority != 100 {
		t.Errorf("expected prerouting priority 100, got %d", *prerouting.Priority)
	}
	if prerouting.Type != nftables.ChainTypeNAT {
		t.Errorf("prerouting must be a NAT chain")
	}

	// postrouting: SNAT 1 + マスカレード 2 + カスタムルート 1 = 4
	if got := len(rulesByChain(rs, "postrouting")); got != 4 {
		t.Errorf("expected 4 postrouting rules, got %d", got)
	}

	// prerouting: forceDNS (1インターフェース × udp/tcp) + DNAT = 3
	preroutingRules := rulesByChain(rs, "prerouting")
	if len(preroutingRules) != 3 {
		t.Fatalf("expected 3 prerouting rules, got %d", len(preroutingRules))
	}

	// DNATルールはNATアドレスにreg1、ポートにreg2を使う
	dnatRule := preroutingRules[len(preroutingRules)-1]
	var nat *expr.NAT
	for _, e := range dnatRule.Exprs {
		if n, ok := e.(*expr.NAT); ok {
			nat = n
		}
	}
	if nat == nil {
		t.Fatal("DNAT rule has no NAT expression")
	}
	if nat.Type != expr.NATTypeDestNAT || nat.RegAddrMin != 1 || nat.RegProtoMin != 2 {
		t.Errorf("unexpected NAT expression: %+v", nat)
	}

	// forceDNSルールはポートを書き換えない（RegProtoMinは0）
	for _, r := range preroutingRules[:2] {
		for _, e := range r.Exprs {
			if n, ok := e.(*expr.NAT); ok && n.RegProtoMin != 0 {
				t.Error("forceDNS rule must not rewrite the port")
			}
		}
	}
}

func TestBuildNatOnlyPreroutingPriority(t *testing.T) {
	cfg := testConfig()
	cfg.Nat = []config.NatConfig{
		{Interface: "wg0", AllowIP: "10.0.0.0/24", DstIP: "10.0.0.1", DstPort: "53", Proto: "udp", NatTo: "192.168.1.100:53"},
	}

	rs, err := Build(cfg)
	if err != nil {
		t.Fatalf("Build returned an error: %v", err)
	}

	prerouting := chainByName(rs, "prerouting")
	if prerouting == nil {
		t.Fatal("prerouting chain not found")
	}
	if *prerouting.Priority != *nftables.ChainPriorityNATDest {
		t.Errorf("expected prerouting priority dstnat(-100), got %d", *prerouting.Priority)
	}
}

func TestBuildErrors(t *testing.T) {
	cases := map[string]func(cfg *config.Config){
		"undefined ipset": func(cfg *config.Config) {
			cfg.Ports[0].AllowIP = "$UNDEFINED"
		},
		"invalid allowIP": func(cfg *config.Config) {
			cfg.Ports[0].AllowIP = "not-an-ip"
		},
		"invalid denyIP": func(cfg *config.Config) {
			cfg.Security.AlwaysDenyIP = []string{"not-an-ip"}
		},
		"invalid protocol": func(cfg *config.Config) {
			cfg.Ports[0].Proto = "sctp"
		},
		"invalid outbound port": func(cfg *config.Config) {
			cfg.Outgoing.Allowed[0].Dport = "not-a-port"
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig()
			mutate(cfg)
			if _, err := Build(cfg); err == nil {
				t.Errorf("expected an error for %s, got nil", name)
			}
		})
	}
}

// TestBuildExprsMarshalは全ての式がnetlink形式にマーシャルできることを検証する
func TestBuildExprsMarshal(t *testing.T) {
	cfg := testConfig()
	cfg.Outgoing.Compatibility = []string{"tailscale", "cloudflare_tunnel"}
	cfg.Router = config.RouterConfig{
		ConfigAsRouter:          true,
		WANInterface:            "eth0",
		PrivateNetworkAddresses: []string{"192.168.10.0/24", "fd11:801::2/64"},
		LANInterfaces:           []string{"eth1", "wg0"},
		ForceDNS:                "192.168.0.1",
		CustomRoutes: []config.CustomRoutesConfig{
			{AllowIP: "10.0.10.0/24", AllowInterface: "wg1", AllowDST: "192.168.10.0/24"},
		},
	}
	cfg.Nat = []config.NatConfig{
		{Interface: "wg0", AllowIP: "10.0.0.0/24", DstIP: "10.0.0.1", DstPort: "53", Proto: "udp", NatTo: "192.168.1.100:53"},
	}
	cfg.Ports = append(cfg.Ports, config.PortConfig{Port: 443, Proto: "tcp", AllowIP: "192.168.1.0/24", AllowInterface: "eth1"})

	rs, err := Build(cfg)
	if err != nil {
		t.Fatalf("Build returned an error: %v", err)
	}

	family := byte(nftables.TableFamilyINet)
	for _, r := range rs.Rules {
		for i, e := range r.Exprs {
			if _, err := expr.Marshal(family, e); err != nil {
				t.Errorf("failed to marshal expr %d in chain %s (%T): %v", i, r.Chain.Name, e, err)
			}
		}
	}
}

func TestMatchAddr(t *testing.T) { // 単一IPv4アドレス（送信元）
	exprs, err := matchAddr("192.168.1.1", true, false)
	if err != nil {
		t.Fatal(err)
	}
	payload, ok := exprs[2].(*expr.Payload)
	if !ok {
		t.Fatal("expected payload expression")
	}
	if payload.Offset != 12 || payload.Len != 4 {
		t.Errorf("unexpected IPv4 saddr payload: %+v", payload)
	}
	cmp := exprs[3].(*expr.Cmp)
	if cmp.Op != expr.CmpOpEq || !bytes.Equal(cmp.Data, []byte{192, 168, 1, 1}) {
		t.Errorf("unexpected cmp: %+v", cmp)
	}

	// IPv4 CIDR（宛先）
	exprs, err = matchAddr("100.64.0.0/10", false, false)
	if err != nil {
		t.Fatal(err)
	}
	payload = exprs[2].(*expr.Payload)
	if payload.Offset != 16 {
		t.Errorf("unexpected IPv4 daddr offset: %d", payload.Offset)
	}
	bitwise, ok := exprs[3].(*expr.Bitwise)
	if !ok {
		t.Fatal("CIDR match must use bitwise")
	}
	if !bytes.Equal(bitwise.Mask, []byte{0xff, 0xc0, 0, 0}) {
		t.Errorf("unexpected mask: %v", bitwise.Mask)
	}
	cmp = exprs[4].(*expr.Cmp)
	if !bytes.Equal(cmp.Data, []byte{100, 64, 0, 0}) {
		t.Errorf("unexpected network: %v", cmp.Data)
	}

	// IPv6アドレス（送信元、否定）
	exprs, err = matchAddr("fd11:801::2", true, true)
	if err != nil {
		t.Fatal(err)
	}
	payload = exprs[2].(*expr.Payload)
	if payload.Offset != 8 || payload.Len != 16 {
		t.Errorf("unexpected IPv6 saddr payload: %+v", payload)
	}
	cmp = exprs[3].(*expr.Cmp)
	if cmp.Op != expr.CmpOpNeq {
		t.Error("negated match must use CmpOpNeq")
	}

	// 不正なアドレスはエラー
	if _, err := matchAddr("invalid", true, false); err == nil {
		t.Error("expected an error for invalid address")
	}
}
