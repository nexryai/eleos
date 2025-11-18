// model.go
package db

import (
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// EmbeddedVulnerability は Product ドキュメントに埋め込まれるサブセットデータです
type EmbeddedVulnerability struct {
	CVE         string    `bson:"cve" json:"cve"`
	GHSA        *string   `bson:"ghsa,omitempty" json:"ghsa,omitempty"`
	PublishedAt time.Time `bson:"publishedAt" json:"publishedAt"`
	// CVSSフィールドをすべて追加
	CVSS40 *int32 `bson:"cvss40,omitempty" json:"cvss40,omitempty"`
	CVSS31 *int32 `bson:"cvss31,omitempty" json:"cvss31,omitempty"`
	CVSS30 *int32 `bson:"cvss30,omitempty" json:"cvss30,omitempty"`
	CVSS20 *int32 `bson:"cvss20,omitempty" json:"cvss20,omitempty"`
}

// Product は製品情報を保持し、最新の脆弱性をサブセットとして持ちます
type Product struct {
	ID                    uuid.UUID               `bson:"_id" json:"id"`
	Name                  string                  `bson:"name" json:"name"`
	RecentVulnerabilities []EmbeddedVulnerability `bson:"recentVulnerabilities" json:"recentVulnerabilities"`
	// ... 他の製品関連フィールド
}

// Vulnerability は脆弱性の完全な履歴データです
type Vulnerability struct {
	ID          bson.ObjectID `bson:"_id,omitempty" json:"id"`
	CVE         string             `bson:"cve" json:"cve"`
	GHSA        *string            `bson:"ghsa,omitempty" json:"ghsa,omitempty"`
	CreatedAt   time.Time          `bson:"createdAt" json:"createdAt"`
	UpdatedAt   time.Time          `bson:"updatedAt" json:"updatedAt"`
	PublishedAt time.Time          `bson:"publishedAt" json:"publishedAt"`
	Description string             `bson:"description" json:"description"`
	CVSS40      *int32             `bson:"cvss40,omitempty" json:"cvss40,omitempty"`
	CVSS31      *int32             `bson:"cvss31,omitempty" json:"cvss31,omitempty"`
	CVSS30      *int32             `bson:"cvss30,omitempty" json:"cvss30,omitempty"`
	CVSS20      *int32             `bson:"cvss20,omitempty" json:"cvss20,omitempty"`
	ProductID   uuid.UUID          `bson:"productId" json:"productId"`
}