package db

import (
	"time"

	"github.com/google/uuid"
)

type Vulnerability struct {
	CVE         string    `json:"cve"`
	GHSA        *string   `json:"ghsa,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
	PublishedAt time.Time `json:"publishedAt"`
	Description string    `json:"description"`
	CVSS40      *int32    `json:"cvss40,omitempty"`
	CVSS31      *int32    `json:"cvss31,omitempty"`
	CVSS30      *int32    `json:"cvss30,omitempty"`
	CVSS20      *int32    `json:"cvss20,omitempty"`
	ProductID   uuid.UUID `json:"productId"`
}
