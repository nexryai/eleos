package render

import (
	"github.com/lorenzosaino/go-sysctl"
	"roscaelum/internal/config"
	"roscaelum/internal/iputil"
	"roscaelum/internal/log"
	"roscaelum/internal/model"
)

/*
nftablesルールをレンダリングする。基本的に1行の内容を1つづつ配列に格納して返す
*/

func containsString(arr []string, target string) bool {
	for _, element := range arr {
		if element == target {
			return true
		}
	}
	return false
}

func GenIpDefineRules(config *config.Config) []string {
	var rules []string

	// ユーザー定義のipsetをロードする
	for _, s := range config.IpSet {
		rules = append(rules, MkDefine(s.Name, s.Ip))
	}

	return rules
}

func GenRulesFromConfig(cfg *config.Config) []string {
	var rules []string

	//テーブル作成
	rules = append(rules, MkTableStart("roscaelum"))

	if cfg.Default.AllowAllIn {
		log.MsgWarn("Input is allowed by default. This is a VERY UNSAFE setting. You MUST not use this setting unless you know what you are doing.")
	}

	// INPUTルール作成
	rules = append(rules,
		MkChainStart("input"),
		MkBaseRules(cfg.Default.AllowAllIn, "input"))

	// これは変えられるようにするべき？
	rules = append(rules,
		MkBaseInputRules(true, true, false),
		MkAllowLoopbackInterface())

	// 不正なパケットとポートスキャンをブロック
	rules = append(rules, MkDropInvalid())
	if !cfg.Security.DisablePortScanProtection {
		rules = append(rules, MkBlockTcpXmas(), MkBlockTcpNull(), MkBlockTcpMss())
	} else {
		log.MsgWarn("Port scan protection is DISABLED!")
	}

	if !cfg.Security.DisableIpFragmentsBlock {
		rules = append(rules, MkBlockIPFragments())
	}

	// alwaysDenyIPを拒否
	for _, denyIP := range cfg.Security.AlwaysDenyIP {
		rules = append(rules, MkDenyIP(denyIP))
	}

	// pingを許可するなら許可
	if cfg.Default.AllowPing {
		rules = append(rules, MkAllowPing(), MkAllowPingICMPv6())
	}

	// IPv6関係
	if cfg.Default.EnableIPv6 {
		rules = append(rules, MkAllowIPv6Ad())
	}

	// SYN-floodレートリミット
	rules = append(rules, MkJumpToSynFloodLimiter())

	// 許可したポートをallow
	for _, r := range cfg.Ports {
		if r.Proto == "" {
			r.Proto = "tcp"
			rules = append(rules, MkAllowPort(&r))
			r.Proto = "udp"
			rules = append(rules, MkAllowPort(&r))
		} else {
			rules = append(rules, MkAllowPort(&r))
		}
	}

	// ログが有効ならログする
	if cfg.Default.EnableLogging {
		rules = append(rules, MkLoggingRules("drop"))
	}

	// INPUTチェーン終了
	rules = append(rules, MkChainEnd())

	// OUTPUTチェーン
	rules = append(rules, MkChainStart("output"),
		MkBaseRules(cfg.Default.AllowAllOut, "output"))

	if !cfg.Default.AllowAllOut {
		// ICMPとループバックは許可
		rules = append(rules, MkAllowLoopbackInterface(),
			MkAllowIcmpOutgoing(),
			MkAllowLocalhostOutgoing())

		// IPv6が有効ならIPv6のICMPも許可
		if cfg.Default.EnableIPv6 {
			rules = append(rules, MkAllowIcmpv6Outgoing())
		}

		for _, r := range cfg.Outgoing.Allowed {
			if r.Proto == "" {
				r.Proto = "tcp"
				rules = append(rules, MkAllowOutgoing(&r))
				r.Proto = "udp"
				rules = append(rules, MkAllowOutgoing(&r))
			} else {
				rules = append(rules, MkAllowOutgoing(&r))
			}
		}

		// Tailscaleと併用できるようにする (https://tailscale.com/kb/1082/firewall-ports)
		//  - 41641への発信と3478への発信を許可する
		if containsString(cfg.Outgoing.Compatibility, "tailscale") {
			rules = append(rules, MkAllowOutgoing(&config.OutgoingAllowConfig{
				Dport: "41641",
				Proto: "udp",
			}), MkAllowOutgoing(&config.OutgoingAllowConfig{
				Dport: "3478",
				Proto: "udp",
			}))
		}

		// Cloudflaredと併用できるようにする
		// https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/deploy-tunnels/tunnel-with-firewall/
		if containsString(cfg.Outgoing.Compatibility, "cloudflare_tunnel") {
			rules = append(rules, MkAllowOutgoing(&config.OutgoingAllowConfig{
				Dport: "7844",
				Proto: "tcp",
			}), MkAllowOutgoing(&config.OutgoingAllowConfig{
				Dport: "7844",
				Proto: "udp",
			}), MkAllowOutgoing(&config.OutgoingAllowConfig{
				Dport: "443",
				Proto: "tcp",
			}))
		}

		// SYNじゃない（=こっちからの発信じゃない）なら許可
		rules = append(rules, MkAllowNonSynOutgoing())

		// ログが有効ならログする
		if cfg.Default.EnableLogging {
			rules = append(rules, MkLoggingForOutgoing())
		}
	}

	rules = append(rules, MkChainEnd())

	// FORWARDチェーン
	rules = append(rules, MkChainStart("forward"))

	if cfg.Default.AllowAllFwd {
		log.MsgWarn("Forwarding is allowed by default. This is an unsafe setting and you usually don't need to do this.")
	}

	rules = append(rules, MkBaseRules(cfg.Default.AllowAllFwd, "forward"))

	// ルーターとして構成するならLAN→WANへのマスカレードを許可する
	if cfg.Router.ConfigAsRouter {
		rules = append(rules, MkBaseInputRules(true, true, false))

		for _, lanInterface := range cfg.Router.LANInterfaces {
			rules = append(rules, MkAllowFwd(lanInterface))
		}

		// カスタムルート設定時にForward許可する
		for _, r := range cfg.Router.CustomRoutes {
			rules = append(rules, MkAllowForwardForCustomRoutes(&r))
		}

	}

	// ポート転送構成時にForwardを許可する
	if len(cfg.Nat) != 0 {
		for _, r := range cfg.Nat {
			rules = append(rules, MkAllowForwardForNat(&r))
		}
	}

	rules = append(rules, MkChainEnd())

	// POSTROUTINGチェーン
	if cfg.Router.ConfigAsRouter || len(cfg.Nat) != 0 {
		sysctlIpForward, err := sysctl.Get("net.ipv4.ip_forward")

		if err != nil {
			log.MsgWarn("Failed to get sysctl value")
		} else if sysctlIpForward == "0" {
			log.MsgWarn("net.ipv4.ip_forward is set to 0.")
		}

		rules = append(rules,
			MkChainStart("postrouting"),
			MkBaseRoutingRule("postrouting"))

		// DNATするときの戻り通信用SNAT
		if len(cfg.Nat) != 0 {
			for _, c := range cfg.Nat {
				internalIP, err := iputil.ExtractIPAddress(c.NatTo)
				if err != nil {
					panic("invalid ip in cfg")
				}

				snat := model.SnatForDnat{
					ExternalInterface: c.Interface,
					InternalIP:        internalIP,
					ExternalIP:        c.DstIP,
				}
				rules = append(rules, MkSnatForDnat(&snat))
			}
		}

		if cfg.Router.ConfigAsRouter {
			// ルーターとして構成するときのLAN→WANのマスカレード
			for _, privateNetworkAddress := range cfg.Router.PrivateNetworkAddresses {
				rules = append(rules, MkMasquerade(privateNetworkAddress, cfg.Router.WANInterface))
			}

			// カスタムルート設定時のマスカレード設定
			for _, r := range cfg.Router.CustomRoutes {
				rules = append(rules, MkMasqueradeForCustomRoutes(&r))
			}
		}

		rules = append(rules, MkChainEnd())
	}

	// PREROUTINGチェーン
	if cfg.Router.ConfigAsRouter || len(cfg.Nat) != 0 {
		rules = append(rules, MkChainStart("prerouting"))

		if cfg.Router.ConfigAsRouter {
			rules = append(rules, MkBaseRoutingRule("prerouting"))
		} else if len(cfg.Nat) != 0 {
			rules = append(rules, MkBaseNatRule())
		}

		if cfg.Router.ForceDNS != "" {
			for _, lanInterface := range cfg.Router.LANInterfaces {
				rules = append(rules, MkForceDNS(cfg.Router.ForceDNS, lanInterface, "udp"))
				rules = append(rules, MkForceDNS(cfg.Router.ForceDNS, lanInterface, "tcp"))
			}
		}

		// ポート転送有効時のNAT構成
		if len(cfg.Nat) != 0 {
			for _, r := range cfg.Nat {
				rules = append(rules, MkNat(&r))
			}
		}

		rules = append(rules, MkChainEnd())
	}

	// SYN-flood対策
	rules = append(rules, MkChainStart("syn-flood"),
		MkRateLimit(30, 60, "SYN-flood"),
		MkChainEnd())

	// テーブル終了
	rules = append(rules, MkTableEnd())

	return rules
}
