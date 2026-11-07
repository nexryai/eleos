package firewall

import (
	"fmt"
	"net"
	"strings"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// TCPのフラグビット
const (
	tcpFlagFin = 0x01
	tcpFlagSyn = 0x02
	tcpFlagRst = 0x04
	tcpFlagPsh = 0x08
	tcpFlagAck = 0x10
	tcpFlagUrg = 0x20
)

// ifnameはインターフェース名をIFNAMSIZ(16バイト)のヌルパディング付きバイト列に変換する
func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, n)
	return b
}

func accept() *expr.Verdict {
	return &expr.Verdict{Kind: expr.VerdictAccept}
}

func drop() *expr.Verdict {
	return &expr.Verdict{Kind: expr.VerdictDrop}
}

// logPrefixはnftablesのログプレフィックスを設定するexpr.Logを生成する
func logPrefix(prefix string) *expr.Log {
	return &expr.Log{Key: 1 << unix.NFTA_LOG_PREFIX, Data: []byte(prefix)}
}

func counter() *expr.Counter {
	return &expr.Counter{}
}

// rateLimitは1秒あたりのパケット数制限を生成する
func rateLimit(rate uint64, burst uint32) *expr.Limit {
	return &expr.Limit{
		Type:  expr.LimitTypePkts,
		Rate:  rate,
		Unit:  expr.LimitTimeSecond,
		Burst: burst,
	}
}

// matchNFProtoはアドレスファミリーのマッチを生成する（nftテキストで暗黙に挿入される依存を明示）
func matchNFProto(ipv4 bool) []expr.Any {
	family := byte(unix.NFPROTO_IPV6)
	if ipv4 {
		family = unix.NFPROTO_IPV4
	}
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{family}},
	}
}

// matchL4はレイヤ4プロトコル（tcp/udp/icmpなど）のマッチを生成する
func matchL4(proto byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
	}
}

// protoNumberはプロトコル名をプロトコル番号に変換する
func protoNumber(proto string) (byte, error) {
	switch proto {
	case "tcp":
		return unix.IPPROTO_TCP, nil
	case "udp":
		return unix.IPPROTO_UDP, nil
	default:
		return 0, fmt.Errorf("unsupported protocol: %s", proto)
	}
}

func matchIIF(name string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(name)},
	}
}

func matchOIF(name string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(name)},
	}
}

// matchDportは宛先ポートのマッチを生成する。L4プロトコルのマッチは別途必要
func matchDport(port uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
	}
}

// matchCtStateはct stateのマッチを生成する（例: established, related）
func matchCtState(bits uint32) []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(bits),
			Xor:            binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
	}
}

// matchTCPFlagsはtcp flags & mask (==|!=) value のマッチを生成する
func matchTCPFlags(mask byte, value byte, negate bool) []expr.Any {
	op := expr.CmpOpEq
	if negate {
		op = expr.CmpOpNeq
	}
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{mask}, Xor: []byte{0}},
		&expr.Cmp{Op: op, Register: 1, Data: []byte{value}},
	}
}

// matchIcmpTypeはICMPタイプのマッチを生成する
func matchIcmpType(ipv4 bool, icmpType byte) []expr.Any {
	var exprs []expr.Any
	if ipv4 {
		exprs = append(exprs, matchNFProto(true)...)
		exprs = append(exprs, matchL4(unix.IPPROTO_ICMP)...)
	} else {
		// ip6 nexthdr icmpv6 と等価
		exprs = append(exprs, matchNFProto(false)...)
		exprs = append(exprs,
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 6, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMPV6}})
	}
	return append(exprs,
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{icmpType}})
}

// matchAddrは送信元/宛先IPアドレスのマッチを生成する。CIDRにも対応する
func matchAddr(addr string, source bool, negate bool) ([]expr.Any, error) {
	var ip net.IP
	var mask net.IPMask

	if strings.Contains(addr, "/") {
		parsedIP, ipNet, err := net.ParseCIDR(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR: %s", addr)
		}
		ip = parsedIP
		mask = ipNet.Mask
	} else {
		ip = net.ParseIP(addr)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address: %s", addr)
		}
	}

	ipv4 := ip.To4() != nil
	var ipBytes []byte
	var offset uint32
	if ipv4 {
		ipBytes = ip.To4()
		if source {
			offset = 12
		} else {
			offset = 16
		}
	} else {
		ipBytes = ip.To16()
		if source {
			offset = 8
		} else {
			offset = 24
		}
	}

	op := expr.CmpOpEq
	if negate {
		op = expr.CmpOpNeq
	}

	exprs := matchNFProto(ipv4)
	exprs = append(exprs,
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: uint32(len(ipBytes))})

	if mask == nil {
		// 単一のIPアドレス
		exprs = append(exprs, &expr.Cmp{Op: op, Register: 1, Data: ipBytes})
	} else {
		// CIDR: マスクしてネットワークアドレスと比較する
		network := ip.Mask(mask)
		if ipv4 {
			network = network.To4()
		} else {
			network = network.To16()
		}
		exprs = append(exprs,
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: uint32(len(ipBytes)), Mask: []byte(mask), Xor: make([]byte, len(ipBytes))},
			&expr.Cmp{Op: op, Register: 1, Data: network})
	}

	return exprs, nil
}
