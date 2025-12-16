package worker

import (
	"fmt"
	"log"
	"math"
	"time"

	"github.com/nexryai/eleos/internal/db"
	"github.com/nexryai/eleos/internal/nvd"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func fetchNewVulnerabilities() (*[]nvd.VulnerabilityItem, error) {
    // last 30 minutes
    start := time.Now().Add(-30 * time.Minute)
    end := time.Now()

	log.Printf("Fetching vulnerabilities modified between %s and %s\n",
		start.Format(time.RFC3339),
		end.Format(time.RFC3339),
	)

	vulnerabilities, err := nvd.FetchVulnerabilities(start, end)
	if err != nil {
		log.Printf("Error fetching vulnerabilities: %v\n", err)
		return nil, fmt.Errorf("error fetching vulnerabilities: %w", err)
	}

	if vulnerabilities == nil || len(*vulnerabilities) == 0 {
		log.Printf("No vulnerabilities found in the specified date range.")
		return nil, nil
	}

	log.Printf("Successfully fetched %d total vulnerabilities!", len(*vulnerabilities))

	return vulnerabilities, nil
}

func checkProductMatch(product Product, configurations []nvd.Configuration) bool {
    // CVEに設定が全くない場合は、マッチしない
    if len(configurations) == 0 {
        return false
    }
    
    // 1つでもマッチするConfigurationがあれば true
    for _, cfg := range configurations {
        if evaluateConfiguration(product, cfg) {
            return true
        }
    }
    
    // どのConfigurationもマッチしなかった
    return false
}

func evaluateConfiguration(product Product, cfg nvd.Configuration) bool {
    if len(cfg.Nodes) == 0 {
        // Nodeがない設定は無効 (マッチしない)
        return false
    }

    isAndOperator := cfg.Operator == "AND"

    for _, node := range cfg.Nodes {
        nodeMatches := evaluateNode(product, node)

        if isAndOperator {
            // AND の場合: 1つでも false なら、このConfigurationは false
            if !nodeMatches {
                return false
            }
        } else {
            // OR の場合: 1つでも true なら、このConfigurationは true
            if nodeMatches {
                return true
            }
        }
    }

    // ループが完了した場合:
    // AND の場合: 全てのnodeが true だった
    // OR  の場合: 全てのnodeが false だった
    return isAndOperator
}

func evaluateNode(product Product, node nvd.Node) bool {
    if len(node.CPEMatch) == 0 {
        // CPEMatchがないNodeは無効 (マッチしない)
        // (注: 'negate' を考慮する場合はここのロジックが変わります)
        return false
    }

    isAndOperator := node.Operator == "AND"

    for _, cpe := range node.CPEMatch {
        // product.CheckCPE のロジックは、
        // 渡された criteria 文字列が製品に該当するかを
        // 判断するものと仮定します。
        cpeMatches := product.CheckCPE(cpe.Criteria)

        if isAndOperator {
            // AND の場合: 1つでも false なら、このNodeは false
            if !cpeMatches {
                return false
            }
        } else {
            // OR の場合: 1つでも true なら、このNodeは true
            if cpeMatches {
                return true
            }
        }
    }

    // ループが完了した場合:
    // AND の場合: 全てのcpeが true だった
    // OR  の場合: 全てのcpeが false だった
    return isAndOperator
}

func processVulnerabilities(vulnerabilities *[]nvd.VulnerabilityItem) (*[]db.Vulnerability, error) {
    fmt.Println("\n--- Displaying results ---")

    dbVulnerabilities := []db.Vulnerability{}


    for _, item := range *vulnerabilities {
        var matchedProductUUID string

        // ProductLoop: 監視対象の各製品をチェック
        for _, product := range products {
            // この製品がCVEのいずれかの設定にマッチするかどうかを評価
            if checkProductMatch(product, item.CVE.Configurations) {
                matchedProductUUID = product.UUID()
                
                // このCVEに対してマッチする製品が見つかったため、
                // 他の製品をチェックする必要はない
                break
            }
        }

        // このCVEにマッチする製品がなかった場合は、次の脆弱性へ
        if matchedProductUUID == "" {
            continue
        }

        // マッチした場合
        fmt.Printf("\nCVE ID: %s\n", item.CVE.ID)
        fmt.Printf("  Matched Product UUID: %s\n", matchedProductUUID)

        // 英語の説明を探して表示
        var enDesc string
        for _, desc := range item.CVE.Descriptions {
            if desc.Lang == "en" {
                enDesc = desc.Value
                break
            }
        }

        if enDesc != "" {
            // if len(enDesc) > 100 {
            // 	fmt.Printf("  Description (en): %s...\n", enDesc[:100])
            // } else {
            // 	fmt.Printf("  Description (en): %s\n", enDesc)
            // }
        } else {
            fmt.Println("  No English description found.")
        }

        var cvss40 int32 = 0
        var cvss31 int32 = 0
        var cvss30 int32 = 0
        var cvss20 int32 = 0

        if len(item.CVE.Metrics.CVSSMetricV40) > 0 {
            base := item.CVE.Metrics.CVSSMetricV40[0].CVSSData.BaseScore
            cvss40 = int32(math.Round(base))
        }

        if len(item.CVE.Metrics.CVSSMetricV31) > 0 {
            base := item.CVE.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
            cvss31 = int32(math.Round(base))
        }

        if len(item.CVE.Metrics.CVSSMetricV2) > 0 {
            base := item.CVE.Metrics.CVSSMetricV2[0].CVSSData.BaseScore
            cvss20 = int32(math.Round(base))
        }

        toPtr := func(v int32) *int32 { return &v }
		productObjectID, err := bson.ObjectIDFromHex(matchedProductUUID)
		if err != nil {
            return nil, fmt.Errorf("invalid object id")
        }

        dbVuln := db.Vulnerability{
            CVE:         item.CVE.ID,
            PublishedAt: item.CVE.Published.Time,
            Description: enDesc,
            CVSS40:      toPtr(cvss40),
            CVSS31:      toPtr(cvss31),
            CVSS30:      toPtr(cvss30),
            CVSS20:      toPtr(cvss20),
            ProductID:   productObjectID,
        }

        dbVulnerabilities = append(dbVulnerabilities, dbVuln)
    }

    return &dbVulnerabilities, nil
}
