// Package firewallはnftablesをnetlink経由で直接操作する。nftコマンドには依存しない
package firewall

import (
	"fmt"

	"github.com/google/nftables"

	"roscaelum/internal/config"
)

// Applyは設定からRulesetを構築し、既存のテーブルを置き換える形でアトミックに適用する
func Apply(cfg *config.Config) error {
	rs, err := Build(cfg)
	if err != nil {
		return err
	}

	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to connect to netlink: %w", err)
	}

	if _, err := deleteTableIfExists(conn); err != nil {
		return err
	}

	conn.AddTable(rs.Table)
	for _, chain := range rs.Chains {
		conn.AddChain(chain)
	}
	for _, rule := range rs.Rules {
		conn.AddRule(rule)
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to apply nftables rules: %w", err)
	}

	return nil
}

// Disableはテーブルを削除してファイアウォールを無効化する。テーブルが存在しない場合は何もしない
func Disable() error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to connect to netlink: %w", err)
	}

	deleted, err := deleteTableIfExists(conn)
	if err != nil {
		return err
	}
	if !deleted {
		return nil
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to delete nftables table: %w", err)
	}

	return nil
}

// deleteTableIfExistsはroscaelumテーブルが存在すれば削除をバッチに積む
func deleteTableIfExists(conn *nftables.Conn) (bool, error) {
	tables, err := conn.ListTables()
	if err != nil {
		return false, fmt.Errorf("failed to list nftables tables: %w", err)
	}

	deleted := false
	for _, table := range tables {
		if table.Name == TableName && table.Family == nftables.TableFamilyINet {
			conn.DelTable(table)
			deleted = true
		}
	}

	return deleted, nil
}
