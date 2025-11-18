// db.go
package db

import (
	"context"
	"fmt"
	"log"
	"time"

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

func CreateDatabaseIndex(ctx context.Context, db *mongo.Database) error {
	log.Print("Starting database index check/creation...")

	vulnCollection := db.Collection("vulnerabilities")

	vulnIndexModel := mongo.IndexModel{
		Keys:    bson.D{{Key: "cve", Value: 1}}, // 1 for ascending order
		Options: options.Index().SetUnique(true),
	}

	indexName, err := vulnCollection.Indexes().CreateOne(ctx, vulnIndexModel)
	if err != nil {
		return fmt.Errorf("failed to create 'cve' index for vulnerabilities: %w", err)
	}

	log.Printf("Index '%s' (vulnerabilities.cve) ensured.", indexName)
	
	log.Print("Index check/creation complete.")
	return nil
}

func CreateVulnerability(ctx context.Context, db *mongo.Database, v *Vulnerability) error {
	log.Print("Starting database session...")
	if db == nil || db.Client() == nil {
		return fmt.Errorf("could not establish database session: client is nil")
	}

	session, err := db.Client().StartSession()
	if err != nil {
		return fmt.Errorf("failed to start database session: %w", err)
	} else {
		log.Print("Database session established.")
	}
	defer session.EndSession(ctx)

	vulnCollection := db.Collection("vulnerabilities")
	prodCollection := db.Collection("products")

	_, err = session.WithTransaction(ctx, func(sessCtx context.Context) (interface{}, error) {
		// FindOne を使用して、同じCVEが存在するかどうかを確認
		err := vulnCollection.FindOne(sessCtx, bson.M{"cve": v.CVE}).Err()
		if err == nil {
			log.Printf("Skipping CVE %s because it already exists.", v.CVE)
			return nil, nil // エラーなしでトランザクションを終了（何もしない）
		}
		if err != mongo.ErrNoDocuments {
			return nil, fmt.Errorf("existing CVE check failed: %s", err)
		}

		now := time.Now()
		v.CreatedAt = now
		v.UpdatedAt = now
		v.ID = bson.NewObjectID()

		if _, err := vulnCollection.InsertOne(sessCtx, v); err != nil {
			return nil, fmt.Errorf("failed to insert document(s) to vulnerabilities collection: %w", err)
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
			return nil, fmt.Errorf("failed to update products collection: %w", err)
		}
		if res.MatchedCount == 0 {
			return nil, fmt.Errorf("no products found matching productId %sん", v.ProductID)
		}

		return nil, nil
	})

	if err != nil {
		return fmt.Errorf("vulnerability registration transaction failed: %w", err)
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
		return fmt.Errorf("failed to start session: %w", err)
	} else {
		log.Print("Database session established.")
	}
	defer session.EndSession(ctx)

	vulnCollection := db.Collection("vulnerabilities")
	prodCollection := db.Collection("products")

	log.Print("Executing transactions..")
	_, err = session.WithTransaction(ctx, func(sessCtx context.Context) (interface{}, error) {
		now := time.Now()


		//処理対象の全CVE IDを収集
		incomingCVEs := make([]string, 0, len(*vulns))
		for _, v := range *vulns {
			if v.CVE != "" {
				incomingCVEs = append(incomingCVEs, v.CVE)
			}
		}

		existingCVEs := make(map[string]struct{})
		if len(incomingCVEs) > 0 {
			filter := bson.M{"cve": bson.M{"$in": incomingCVEs}}
			// 必要なのはCVEフィールドだけなので、Projectionで効率化
			opts := options.Find().SetProjection(bson.M{"cve": 1, "_id": 0})
			cursor, err := vulnCollection.Find(sessCtx, filter, opts)
			if err != nil {
				return nil, fmt.Errorf("search for existing cve failed: %w", err)
			}
			defer cursor.Close(sessCtx)

			for cursor.Next(sessCtx) {
				var result struct {
					CVE string `bson:"cve"`
				}
				if err := cursor.Decode(&result); err != nil {
					return nil, fmt.Errorf("failed to decode in cursor: %w", err)
				}
				existingCVEs[result.CVE] = struct{}{}
			}
			if err := cursor.Err(); err != nil {
				return nil, fmt.Errorf("cursor error: %w", err)
			}
		}

		vulnDocs := make([]interface{}, 0)
		prodVulnsMap := make(map[bson.ObjectID][]EmbeddedVulnerability)
		newVulnsFoundCount := 0

		for i := range *vulns {
			v := &(*vulns)[i]

			if _, exists := existingCVEs[v.CVE]; exists {
				log.Printf("Skipping CVE %s because it already exists.", v.CVE)
				continue // 存在する場合はスキップ
			}

			newVulnsFoundCount++
			v.CreatedAt = now
			v.UpdatedAt = now
			v.ID = bson.NewObjectID()

			vulnDocs = append(vulnDocs, v) // InsertManyの対象に追加

			embeddedVuln := EmbeddedVulnerability{
				CVE:         v.CVE,
				GHSA:        v.GHSA,
				PublishedAt: v.PublishedAt,
				CVSS40:      v.CVSS40,
				CVSS31:      v.CVSS31,
				CVSS30:      v.CVSS30,
				CVSS20:      v.CVSS20,
			}
			// ProductIDごとにEmbeddedVulnerabilityをまとめる
			prodVulnsMap[v.ProductID] = append(prodVulnsMap[v.ProductID], embeddedVuln)
		}

		if newVulnsFoundCount == 0 {
			return nil, nil
		}

		if _, err := vulnCollection.InsertMany(sessCtx, vulnDocs); err != nil {
			return nil, fmt.Errorf("insert many: failed: %w", err)
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
				return nil, fmt.Errorf("bulk vulnerability registration transaction failed: %w", err)
			}
		}

		return nil, nil
	})

	if err != nil {
		return fmt.Errorf("脆弱性一括登録トランザクションが失敗しました: %w", err)
	}

	log.Print("Transaction succeeded!") // <--- ログを少し変更
	return nil
}