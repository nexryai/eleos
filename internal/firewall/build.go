package firewall

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/lorenzosaino/go-sysctl"
	"golang.org/x/sys/unix"

	"roscaelum/internal/config"
	"roscaelum/internal/iputil"
	"roscaelum/internal/log"
)

// TableNameはnftablesのテーブル名
const TableName = "roscaelum"

// Rulesetは適用対象のテーブル・チェーン・ルールの集合
type Ruleset struct {
	Table  *nftables.Table
	Chains []*nftables.Chain
	Rules  []*nftables.Rule
}

type builder struct {
	cfg    *config.Config
	ipsets map[string][]string
	rs     *Ruleset
	chains map[string]*nftables.Chain
}

func (b *builder) addChain(chain *nftables.Chain) {
	b.rs.Chains = append(b.rs.Chains, chain)
	b.chains[chain.Name] = chain
}

func (b *builder) add(chain string, exprs ...expr.Any) {
	b.rs.Rules = append(b.rs.Rules, &nftables.Rule{
		Table: b.rs.Table,
		Chain: b.chains[chain],
		Exprs: exprs,
	})
}

func baseChain(table *nftables.Table, name string, hook *nftables.ChainHook, chainType nftables.ChainType, priority *nftables.ChainPriority, policy nftables.ChainPolicy) *nftables.Chain {
	return &nftables.Chain{
		Table:    table,
		Name:     name,
		Type:     chainType,
		Hooknum:  hook,
		Priority: priority,
		Policy:   &policy,
	}
}

func chainPolicy(allowAll bool) nftables.ChainPolicy {
	if allowAll {
		return nftables.ChainPolicyAccept
	}
	return nftables.ChainPolicyDrop
}

// Buildは設定からRulesetを構築する。netlink通信は行わない
func Build(cfg *config.Config) (*Ruleset, error) {
	b := &builder{
		cfg:    cfg,
		ipsets: make(map[string][]string),
		chains: make(map[string]*nftables.Chain),
		rs: &Ruleset{
			Table: &nftables.Table{Name: TableName, Family: nftables.TableFamilyINet},
		},
	}

	for _, s := range cfg.IpSet {
		b.ipsets[s.Name] = s.Ip
	}

	b.addChain(baseChain(b.rs.Table, "input", nftables.ChainHookInput, nftables.ChainTypeFilter, nftables.ChainPriorityFilter, chainPolicy(cfg.Default.AllowAllIn)))
	b.addChain(baseChain(b.rs.Table, "output", nftables.ChainHookOutput, nftables.ChainTypeFilter, nftables.ChainPriorityFilter, chainPolicy(cfg.Default.AllowAllOut)))
	b.addChain(baseChain(b.rs.Table, "forward", nftables.ChainHookForward, nftables.ChainTypeFilter, nftables.ChainPriorityFilter, chainPolicy(cfg.Default.AllowAllFwd)))
	b.addChain(&nftables.Chain{Table: b.rs.Table, Name: "syn-flood"})

	if cfg.Router.ConfigAsRouter || len(cfg.Nat) != 0 {
		acceptPolicy := nftables.ChainPolicyAccept
		b.addChain(baseChain(b.rs.Table, "postrouting", nftables.ChainHookPostrouting, nftables.ChainTypeNAT, nftables.ChainPriorityNATSource, acceptPolicy))

		// ルーター構成時はpriority 100、NATのみの場合はdstnat(-100)
		preroutingPriority := nftables.ChainPriorityNATDest
		if cfg.Router.ConfigAsRouter {
			preroutingPriority = nftables.ChainPriorityNATSource
		}
		b.addChain(baseChain(b.rs.Table, "prerouting", nftables.ChainHookPrerouting, nftables.ChainTypeNAT, preroutingPriority, acceptPolicy))
	}

	if err := b.buildInput(); err != nil {
		return nil, err
	}
	if err := b.buildOutput(); err != nil {
		return nil, err
	}
	if err := b.buildForward(); err != nil {
		return nil, err
	}
	if err := b.buildNat(); err != nil {
		return nil, err
	}
	b.buildSynFlood()

	return b.rs, nil
}

// allowPortはポート許可ルールを生成する。allowIPがipsetを参照する場合は要素ごとに展開する
func (b *builder) allowPort(chain string, p *config.PortConfig, proto string) error {
	protoNum, err := protoNumber(proto)
	if err != nil {
		return err
	}

	base := []expr.Any{}
	if p.AllowInterface != "" {
		base = append(base, matchIIF(p.AllowInterface)...)
	}
	base = append(base, matchL4(protoNum)...)
	base = append(base, matchDport(uint16(p.Port))...)

	targets := []string{""}
	if p.AllowIP != "" {
		if strings.HasPrefix(p.AllowIP, "$") {
			name := strings.TrimPrefix(p.AllowIP, "$")
			set, ok := b.ipsets[name]
			if !ok {
				return fmt.Errorf("undefined ipset: $%s", name)
			}
			targets = set
		} else {
			targets = []string{p.AllowIP}
		}
	}

	for _, target := range targets {
		exprs := append([]expr.Any{}, base...)
		if target != "" {
			m, err := matchAddr(target, true, false)
			if err != nil {
				return err
			}
			exprs = append(exprs, m...)
		}
		exprs = append(exprs, accept())
		b.add(chain, exprs...)
	}

	return nil
}

// allowOutgoingはアウトバウンドの許可ルールを生成する
func (b *builder) allowOutgoing(r *config.OutgoingAllowConfig) error {
	proto := r.Proto
	if proto == "" {
		if err := b.allowOutgoing(&config.OutgoingAllowConfig{Dport: r.Dport, Proto: "tcp", DstIP: r.DstIP}); err != nil {
			return err
		}
		return b.allowOutgoing(&config.OutgoingAllowConfig{Dport: r.Dport, Proto: "udp", DstIP: r.DstIP})
	}

	protoNum, err := protoNumber(proto)
	if err != nil {
		return err
	}

	port, err := strconv.ParseUint(r.Dport, 10, 16)
	if err != nil {
		return fmt.Errorf("invalid port: %s", r.Dport)
	}

	exprs := matchL4(protoNum)
	exprs = append(exprs, matchDport(uint16(port))...)
	if r.DstIP != "" {
		m, err := matchAddr(r.DstIP, false, false)
		if err != nil {
			return err
		}
		exprs = append(exprs, m...)
	}
	exprs = append(exprs, accept())
	b.add("output", exprs...)
	return nil
}

func (b *builder) buildInput() error {
	cfg := b.cfg

	if cfg.Default.AllowAllIn {
		log.MsgWarn("Input is allowed by default. This is a VERY UNSAFE setting. You MUST not use this setting unless you know what you are doing.")
	}

	// 確立済み・関連の接続は許可し、不正なパケットはログを残して落とす
	b.add("input", append(matchCtState(expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED), accept())...)
	b.add("input", append(matchCtState(expr.CtStateBitINVALID),
		logPrefix("[roscaelum] Drop invalid packet: "), drop())...)
	b.add("input", append(matchIIF("lo"), accept())...)

	// SYNではない新規接続をブロック
	b.add("input", append(append(matchL4(unix.IPPROTO_TCP),
		append(matchTCPFlags(tcpFlagFin|tcpFlagSyn|tcpFlagRst|tcpFlagPsh|tcpFlagAck, tcpFlagSyn, true),
			matchCtState(expr.CtStateBitNEW)...)...),
		logPrefix("[roscaelum] Drop invalid packet: "), drop())...)

	// ポートスキャンをブロック
	if !cfg.Security.DisablePortScanProtection {
		b.add("input", append(append(matchL4(unix.IPPROTO_TCP), matchTCPFlags(tcpFlagFin|tcpFlagPsh|tcpFlagUrg, tcpFlagFin|tcpFlagPsh|tcpFlagUrg, false)...),
			logPrefix("[roscaelum] TCP XMAS blocked: "), counter(), drop())...)
		b.add("input", append(append(matchL4(unix.IPPROTO_TCP), matchTCPFlags(tcpFlagFin|tcpFlagSyn|tcpFlagRst|tcpFlagPsh|tcpFlagAck|tcpFlagUrg, 0, false)...),
			logPrefix("[roscaelum] TCP NULL blocked: "), counter(), drop())...)

		// SYNパケットで異常に小さいMSSを持つものをブロック
		mssMatch := append(matchL4(unix.IPPROTO_TCP), matchTCPFlags(tcpFlagFin|tcpFlagSyn|tcpFlagRst|tcpFlagPsh|tcpFlagAck|tcpFlagUrg, tcpFlagSyn, false)...)
		mssMatch = append(mssMatch,
			&expr.Exthdr{DestRegister: 1, Type: 2, Offset: 2, Len: 2, Op: expr.ExthdrOpTcpopt},
			&expr.Cmp{Op: expr.CmpOpGte, Register: 1, Data: []byte{0, 1}},
			&expr.Cmp{Op: expr.CmpOpLte, Register: 1, Data: []byte{2, 23}})
		b.add("input", append(mssMatch,
			logPrefix("[roscaelum] TCP MSS blocked: "), counter(), drop())...)
	} else {
		log.MsgWarn("Port scan protection is DISABLED!")
	}

	// IPフラグメントをブロック
	if !cfg.Security.DisableIpFragmentsBlock {
		fragmentMatch := append(matchNFProto(true),
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 6, Len: 2},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 2, Mask: []byte{0x1f, 0xff}, Xor: []byte{0, 0}},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0}})
		b.add("input", append(fragmentMatch,
			logPrefix("[roscaelum] IP FRAGMENTS detected and blocked: "), counter(), drop())...)
	}

	// alwaysDenyIPを拒否
	for _, denyIP := range cfg.Security.AlwaysDenyIP {
		m, err := matchAddr(denyIP, true, false)
		if err != nil {
			return err
		}
		b.add("input", append(m, drop())...)
	}

	// pingを許可する（レートリミット超過分はログを残して落とす）
	if cfg.Default.AllowPing {
		for _, ipv4 := range []bool{true, false} {
			icmpType := byte(128)
			prefix := "[roscaelum] icmpv6 echo-request rate limit exceeded: "
			if ipv4 {
				icmpType = 8
				prefix = "[roscaelum] icmp echo-request rate limit exceeded: "
			}
			b.add("input", append(matchIcmpType(ipv4, icmpType), rateLimit(4, 5), accept())...)
			b.add("input", append(matchIcmpType(ipv4, icmpType), logPrefix(prefix), counter(), drop())...)
		}
	}

	// IPv6の近隣探索を許可（これを許可しないとIPv6関係の接続が壊れる）
	if cfg.Default.EnableIPv6 {
		for _, t := range []byte{135, 134, 136} {
			b.add("input", append(matchIcmpType(false, t), accept())...)
		}
	}

	// SYN-floodレートリミットへジャンプ
	b.add("input", append(append(matchL4(unix.IPPROTO_TCP), matchTCPFlags(tcpFlagFin|tcpFlagSyn|tcpFlagRst|tcpFlagAck, tcpFlagSyn, false)...),
		counter(), &expr.Verdict{Kind: expr.VerdictJump, Chain: "syn-flood"})...)

	// 許可したポートをallow
	for _, p := range cfg.Ports {
		if p.Proto == "" {
			if err := b.allowPort("input", &p, "tcp"); err != nil {
				return err
			}
			if err := b.allowPort("input", &p, "udp"); err != nil {
				return err
			}
		} else {
			if err := b.allowPort("input", &p, p.Proto); err != nil {
				return err
			}
		}
	}

	// ログが有効ならログする
	if cfg.Default.EnableLogging {
		b.add("input", logPrefix("[roscaelum] Access Denied: "), counter(), drop())
	}

	return nil
}

func (b *builder) buildOutput() error {
	cfg := b.cfg

	if cfg.Default.AllowAllOut {
		return nil
	}

	b.add("output", append(matchIIF("lo"), accept())...)
	b.add("output", append(append(matchNFProto(true), matchL4(unix.IPPROTO_ICMP)...), accept())...)

	localhost, err := matchAddr("127.0.0.1", false, false)
	if err != nil {
		return err
	}
	b.add("output", append(localhost, accept())...)

	if cfg.Default.EnableIPv6 {
		for _, t := range []byte{128, 129, 135, 136, 133, 134, 130, 1, 2, 3, 4} {
			b.add("output", append(matchIcmpType(false, t), accept())...)
		}
	}

	for _, r := range cfg.Outgoing.Allowed {
		if err := b.allowOutgoing(&r); err != nil {
			return err
		}
	}

	// Tailscaleと併用できるようにする (https://tailscale.com/kb/1082/firewall-ports)
	if containsString(cfg.Outgoing.Compatibility, "tailscale") {
		for _, port := range []string{"41641", "3478"} {
			if err := b.allowOutgoing(&config.OutgoingAllowConfig{Dport: port, Proto: "udp"}); err != nil {
				return err
			}
		}
	}

	// Cloudflaredと併用できるようにする
	if containsString(cfg.Outgoing.Compatibility, "cloudflare_tunnel") {
		for _, r := range []config.OutgoingAllowConfig{
			{Dport: "7844", Proto: "tcp"},
			{Dport: "7844", Proto: "udp"},
			{Dport: "443", Proto: "tcp"},
		} {
			r := r
			if err := b.allowOutgoing(&r); err != nil {
				return err
			}
		}
	}

	// SYNじゃない（=こっちからの発信じゃない）なら許可
	b.add("output", append(append(matchL4(unix.IPPROTO_TCP), matchTCPFlags(tcpFlagFin|tcpFlagSyn|tcpFlagRst|tcpFlagPsh|tcpFlagAck, tcpFlagSyn, true)...), accept())...)

	if cfg.Default.EnableLogging {
		b.add("output", logPrefix("[roscaelum] Not allowed syn-packet was dropped: "), counter(), drop())
	}

	return nil
}

func (b *builder) buildForward() error {
	cfg := b.cfg

	if cfg.Default.AllowAllFwd {
		log.MsgWarn("Forwarding is allowed by default. This is an unsafe setting and you usually don't need to do this.")
	}

	if cfg.Router.ConfigAsRouter {
		b.add("forward", append(matchCtState(expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED), accept())...)
		b.add("forward", append(matchCtState(expr.CtStateBitINVALID), drop())...)

		for _, lanInterface := range cfg.Router.LANInterfaces {
			b.add("forward", append(matchIIF(lanInterface), accept())...)
		}

		for _, r := range cfg.Router.CustomRoutes {
			exprs := matchIIF(r.AllowInterface)
			m, err := matchAddr(r.AllowIP, true, false)
			if err != nil {
				return err
			}
			exprs = append(exprs, m...)
			m, err = matchAddr(r.AllowDST, false, false)
			if err != nil {
				return err
			}
			exprs = append(exprs, m...)
			b.add("forward", append(exprs, accept())...)
		}
	}

	for _, r := range cfg.Nat {
		exprs := matchIIF(r.Interface)
		m, err := matchAddr(r.AllowIP, true, false)
		if err != nil {
			return err
		}
		exprs = append(exprs, m...)
		b.add("forward", append(exprs, accept())...)
	}

	return nil
}

func (b *builder) buildNat() error {
	cfg := b.cfg

	if !cfg.Router.ConfigAsRouter && len(cfg.Nat) == 0 {
		return nil
	}

	sysctlIpForward, err := sysctl.Get("net.ipv4.ip_forward")
	if err != nil {
		log.MsgWarn("Failed to get sysctl value")
	} else if sysctlIpForward == "0" {
		log.MsgWarn("net.ipv4.ip_forward is set to 0.")
	}

	// DNATするときの戻り通信用SNAT
	for _, c := range cfg.Nat {
		internalIP, err := iputil.ExtractIPAddress(c.NatTo)
		if err != nil {
			return fmt.Errorf("invalid natTo in config: %s", c.NatTo)
		}
		externalIP := net.ParseIP(c.DstIP)
		if externalIP == nil || externalIP.To4() == nil {
			return fmt.Errorf("invalid dstIP in config: %s", c.DstIP)
		}
		sourceMatch, err := matchAddr(internalIP, true, false)
		if err != nil {
			return err
		}
		exprs := append(matchOIF(c.Interface), sourceMatch...)
		exprs = append(exprs, counter(),
			&expr.Immediate{Register: 1, Data: externalIP.To4()},
			&expr.NAT{Type: expr.NATTypeSourceNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: 1})
		b.add("postrouting", exprs...)
	}

	if cfg.Router.ConfigAsRouter {
		for _, privateNetworkAddress := range cfg.Router.PrivateNetworkAddresses {
			m, err := matchAddr(privateNetworkAddress, true, false)
			if err != nil {
				return err
			}
			b.add("postrouting", append(append(m, matchOIF(cfg.Router.WANInterface)...), &expr.Masq{})...)
		}

		for _, r := range cfg.Router.CustomRoutes {
			exprs := matchIIF(r.AllowInterface)
			m, err := matchAddr(r.AllowIP, true, false)
			if err != nil {
				return err
			}
			exprs = append(exprs, m...)
			m, err = matchAddr(r.AllowDST, false, false)
			if err != nil {
				return err
			}
			exprs = append(exprs, m...)
			b.add("postrouting", append(exprs, &expr.Masq{})...)
		}
	}

	// LAN内のデバイスに特定のDNSを強制する
	if cfg.Router.ForceDNS != "" {
		dnsIP := net.ParseIP(cfg.Router.ForceDNS)
		if dnsIP == nil || dnsIP.To4() == nil {
			return fmt.Errorf("invalid forceDNS address: %s", cfg.Router.ForceDNS)
		}
		for _, lanInterface := range cfg.Router.LANInterfaces {
			for _, proto := range []byte{unix.IPPROTO_UDP, unix.IPPROTO_TCP} {
				exprs := append(matchIIF(lanInterface), matchL4(proto)...)
				notLocalhost, err := matchAddr("127.0.0.1", true, true)
				if err != nil {
					return err
				}
				exprs = append(exprs, notLocalhost...)
				notDNS, err := matchAddr(cfg.Router.ForceDNS, false, true)
				if err != nil {
					return err
				}
				exprs = append(exprs, notDNS...)
				exprs = append(exprs, matchDport(53)...)
				exprs = append(exprs,
					&expr.Immediate{Register: 1, Data: dnsIP.To4()},
					&expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: 1})
				b.add("prerouting", exprs...)
			}
		}
	}

	// ポート転送
	for _, c := range cfg.Nat {
		protoNum, err := protoNumber(c.Proto)
		if err != nil {
			return err
		}
		dstPort, err := strconv.ParseUint(c.DstPort, 10, 16)
		if err != nil {
			return fmt.Errorf("invalid dstPort in config: %s", c.DstPort)
		}
		_, natToPortStr, err := net.SplitHostPort(c.NatTo)
		if err != nil {
			return fmt.Errorf("invalid natTo in config: %s", c.NatTo)
		}
		natToPort, err := strconv.ParseUint(natToPortStr, 10, 16)
		if err != nil {
			return fmt.Errorf("invalid natTo in config: %s", c.NatTo)
		}
		natToIP, err := iputil.ExtractIPAddress(c.NatTo)
		if err != nil {
			return fmt.Errorf("invalid natTo in config: %s", c.NatTo)
		}
		dstIP := net.ParseIP(c.DstIP)
		if dstIP == nil || dstIP.To4() == nil {
			return fmt.Errorf("invalid dstIP in config: %s", c.DstIP)
		}

		exprs := matchIIF(c.Interface)
		if c.AllowIP != "" {
			m, err := matchAddr(c.AllowIP, true, false)
			if err != nil {
				return err
			}
			exprs = append(exprs, m...)
		}
		dstMatch, err := matchAddr(c.DstIP, false, false)
		if err != nil {
			return err
		}
		exprs = append(exprs, dstMatch...)
		exprs = append(exprs, matchL4(protoNum)...)
		exprs = append(exprs, matchDport(uint16(dstPort))...)
		exprs = append(exprs,
			&expr.Immediate{Register: 1, Data: net.ParseIP(natToIP).To4()},
			&expr.Immediate{Register: 2, Data: []byte{byte(natToPort >> 8), byte(natToPort)}},
			&expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: 1, RegProtoMin: 2})
		b.add("prerouting", exprs...)
	}

	return nil
}

func (b *builder) buildSynFlood() {
	b.add("syn-flood", rateLimit(30, 60), counter(), &expr.Verdict{Kind: expr.VerdictReturn})
	b.add("syn-flood", logPrefix("[roscaelum] SYN-flood attack mitigated: "), counter(), drop())
}

func containsString(arr []string, target string) bool {
	for _, element := range arr {
		if element == target {
			return true
		}
	}
	return false
}
