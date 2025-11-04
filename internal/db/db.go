package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

func NewDBConn(ctx context.Context, connString string) (*pgx.Conn, error) {
	conn, err := pgx.Connect(ctx, connString)
	if err != nil {
		return nil, fmt.Errorf("DBに接続できませんでした: %w", err)
	}

	// Ping
	if err = conn.Ping(ctx); err != nil {
		conn.Close(ctx) // 失敗したら接続を閉じる
		return nil, fmt.Errorf("DBにPingできませんでした: %w", err)
	}

	return conn, nil
}

func CreateVulnerability(ctx context.Context, conn *pgx.Conn, v *Vulnerability) error {
	query := `
		INSERT INTO "Vulnerability" (
			"cve", "ghsa", "publishedAt", "description", 
			"cvss40", "cvss31", "cvss30", "cvss20", "productId"
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING "createdAt", "updatedAt"
	`

	err := conn.QueryRow(ctx, query,
		v.CVE,
		v.GHSA,
		v.PublishedAt,
		v.Description,
		v.CVSS40,
		v.CVSS31,
		v.CVSS30,
		v.CVSS20,
		v.ProductID,
	).Scan(&v.CreatedAt, &v.UpdatedAt)

	if err != nil {
		return fmt.Errorf("レコードの挿入に失敗しました: %w", err)
	}

	return nil
}

// CreateVulnerabilityBatch は複数の脆弱性を一括で登録します
func CreateVulnerabilityBatch(ctx context.Context, conn *pgx.Conn, vulns *[]Vulnerability) error {
	// トランザクションを開始
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("トランザクションの開始に失敗しました: %w", err)
	}
	defer tx.Rollback(ctx) // 関数終了時にロールバックを試みる（commitされている場合は無視される）

	// COPY文を使用して一括挿入
	_, err = tx.CopyFrom(
		ctx,
		pgx.Identifier{"Vulnerability"},
		[]string{
			"cve",
			"ghsa",
			"publishedAt",
			"description",
			"cvss40",
			"cvss31",
			"cvss30",
			"cvss20",
			"productId",
		},
		pgx.CopyFromSlice(len(*vulns), func(i int) ([]interface{}, error) {
			v := (*vulns)[i]
			return []interface{}{
				v.CVE,
				v.GHSA,
				v.PublishedAt,
				v.Description,
				v.CVSS40,
				v.CVSS31,
				v.CVSS30,
				v.CVSS20,
				v.ProductID,
			}, nil
		}),
	)

	if err != nil {
		return fmt.Errorf("一括挿入に失敗しました: %w", err)
	}

	// トランザクションをコミット
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("トランザクションのコミットに失敗しました: %w", err)
	}

	// 現在の時刻を設定
	now := time.Now()
	for i := range *vulns {
		(*vulns)[i].CreatedAt = now
		(*vulns)[i].UpdatedAt = now
	}

	return nil
}
