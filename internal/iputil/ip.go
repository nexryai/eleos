package iputil

import (
	"fmt"
	"net"
	"regexp"
)

// stringが有効なIPアドレスか識別する
func isValidIP(ip string) bool {
	if _, _, err := net.ParseCIDR(ip); err == nil {
		return true
	}
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil
}

func ExtractIPAddress(input string) (string, error) {
	// IPアドレスの正規表現パターン
	ipPattern := `(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`

	// 正規表現にマッチする部分を抽出
	re := regexp.MustCompile(ipPattern)
	matches := re.FindStringSubmatch(input)

	// マッチが見つからなかった場合
	if len(matches) < 2 {
		return "", fmt.Errorf("no ip found")
	}

	if !isValidIP(matches[1]) {
		return "", fmt.Errorf("invalid ip found")
	}

	// 抽出したIPアドレスを返す
	return matches[1], nil
}
