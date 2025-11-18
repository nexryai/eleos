// db.go
package db

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const MaxRecentVulnerabilities = 5

func NewDBClient(ctx context.Context, uri string, dbName string) (*mongo.Database, error) {
	clientOptions := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(clientOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err = client.Ping(ctx, nil); err != nil {
		client.Disconnect(ctx)
		return nil, fmt.Errorf("failed to ping the database: %w", err)
	}

	log.Print("Connected to MongoDB!")

	return client.Database(dbName), nil
}

func CreateVulnerability(ctx context.Context, db *mongo.Database, v *Vulnerability) error {
	session, err := db.Client().StartSession()
	if err != nil {
		return fmt.Errorf("セッションの開始に失敗しました: %w", err)
	}
	defer session.EndSession(ctx)

	vulnCollection := db.Collection("vulnerabilities")
	prodCollection := db.Collection("products")

	_, err = session.WithTransaction(ctx, func(sessCtx context.Context) (interface{}, error) {
		now := time.Now()
		v.CreatedAt = now
		v.UpdatedAt = now
		v.ID = bson.NewObjectID()

		if _, err := vulnCollection.InsertOne(sessCtx, v); err != nil {
			return nil, fmt.Errorf("vulnerabilities への挿入に失敗しました: %w", err)
		}

		embeddedVuln := EmbeddedVulnerability{
			CVE:         v.CVE,
			GHSA:        v.GHSA,
			PublishedAt: v.PublishedAt,
			CVSS40:      v.CVSS40,
			CVSS31:      v.CVSS31,
			CVSS30:      v.CVSS30,
			CVSS20:      v.CVSS20,
		}

		update := bson.M{
			"$push": bson.M{
				"recentVulnerabilities": bson.M{
					"$each":  []EmbeddedVulnerability{embeddedVuln},
					"$sort":  bson.M{"publishedAt": -1},
					"$slice": MaxRecentVulnerabilities,
				},
			},
		}
		filter := bson.M{"_id": v.ProductID}

		res, err := prodCollection.UpdateOne(sessCtx, filter, update)
		if err != nil {
			return nil, fmt.Errorf("products の更新に失敗しました: %w", err)
		}
		if res.MatchedCount == 0 {
			return nil, fmt.Errorf("productId %s に一致する製品が見つかりません", v.ProductID)
		}

		return nil, nil
	})

	if err != nil {
		return fmt.Errorf("脆弱性登録トランザクションが失敗しました: %w", err)
	}

	return nil
}

func CreateVulnerabilityBatch(ctx context.Context, db *mongo.Database, vulns *[]Vulnerability) error {
	if len(*vulns) == 0 {
		return nil
	}

	log.Print("Starting database session...")
	if db == nil || db.Client() == nil {
		return fmt.Errorf("could not establish database session: client is nil")
	}

	session, err := db.Client().StartSession()
	if err != nil {
		return fmt.Errorf("セッションの開始に失敗しました: %w", err)
	} else {
		log.Print("Database session established.")
	}
	defer session.EndSession(ctx)

	vulnCollection := db.Collection("vulnerabilities")
	prodCollection := db.Collection("products")

	_, err = session.WithTransaction(ctx, func(sessCtx context.Context) (interface{}, error) {
		now := time.Now()
		
		vulnDocs := make([]interface{}, len(*vulns))
		prodVulnsMap := make(map[uuid.UUID][]EmbeddedVulnerability)

		for i := range *vulns {
			v := &(*vulns)[i]
			v.CreatedAt = now
			v.UpdatedAt = now
			v.ID = bson.NewObjectID()
			
			vulnDocs[i] = v

			embeddedVuln := EmbeddedVulnerability{
				CVE:         v.CVE,
				GHSA:        v.GHSA,
				PublishedAt: v.PublishedAt,
				CVSS40:      v.CVSS40,
				CVSS31:      v.CVSS31,
				CVSS30:      v.CVSS30,
				CVSS20:      v.CVSS20,
			}
			prodVulnsMap[v.ProductID] = append(prodVulnsMap[v.ProductID], embeddedVuln)
		}

		if _, err := vulnCollection.InsertMany(sessCtx, vulnDocs); err != nil {
			return nil, fmt.Errorf("vulnerabilities への一括挿入に失敗しました: %w", err)
		}

		var productUpdates []mongo.WriteModel
		for prodID, newVulns := range prodVulnsMap {
			filter := bson.M{"_id": prodID}
			update := bson.M{
				"$push": bson.M{
					"recentVulnerabilities": bson.M{
						"$each":  newVulns,
						"$sort":  bson.M{"publishedAt": -1},
						"$slice": MaxRecentVulnerabilities,
					},
				},
			}
			model := mongo.NewUpdateOneModel().SetFilter(filter).SetUpdate(update)
			productUpdates = append(productUpdates, model)
		}

		if len(productUpdates) > 0 {
			if _, err := prodCollection.BulkWrite(sessCtx, productUpdates); err != nil {
				return nil, fmt.Errorf("products の一括更新に失敗しました: %w", err)
			}
		}

		return nil, nil
	})

	if err != nil {
		return fmt.Errorf("脆弱性一括登録トランザクションが失敗しました: %w", err)
	}
	
	return nil
}