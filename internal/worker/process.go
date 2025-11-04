package worker

import (
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/nexryai/eleos/internal/db"
	"github.com/nexryai/eleos/internal/nvd"
)

func fetchNewVulnerabilities() (*[]nvd.VulnerabilityItem, error) {
	start := time.Date(2025, 9, 25, 15, 45, 0, 0, time.UTC)
	end := time.Date(2025, 9, 25, 16, 00, 0, 0, time.UTC)

	fmt.Printf("Fetching vulnerabilities modified between %s and %s\n",
		start.Format(time.RFC3339),
		end.Format(time.RFC3339),
	)

	vulnerabilities, err := nvd.FetchVulnerabilities(start, end)
	if err != nil {
		fmt.Printf("Error fetching vulnerabilities: %v\n", err)
		return nil, fmt.Errorf("error fetching vulnerabilities: %w", err)
	}

	if vulnerabilities == nil || len(*vulnerabilities) == 0 {
		fmt.Println("No vulnerabilities found in the specified date range.")
		return nil, nil
	}

	fmt.Printf("\nSuccessfully fetched %d total vulnerabilities.\n", len(*vulnerabilities))

	return vulnerabilities, nil
}

// processVulnerabilities は、取得した脆弱性情報を製品リストと照合し、マッチしたものを変換して返却します。
func processVulnerabilities(vulnerabilities *[]nvd.VulnerabilityItem) (*[]db.Vulnerability, error) {
	fmt.Println("\n--- Displaying results ---")

	dbVulnerabilities := []db.Vulnerability{}

	for _, item := range *vulnerabilities {
		var matchedProduct string

	ProductLoop:
		for _, product := range products {

			for _, cfg := range item.CVE.Configurations {
				// OperatorがANDの場合、
				shouldMatchAllNodes := cfg.Operator == "AND"

			NodeLoop:
				for _, node := range cfg.Nodes {
					shouldMatchAllCPEs := cfg.Operator == "AND"

				CPEMatchLoop:
					for _, cpe := range node.CPEMatch {
						if product.CheckCPE(cpe.Criteria) {
							fmt.Printf("Product %s matched for CVE ID: %s\n", product.UUID(), item.CVE.ID)
							matchedProduct = product.UUID()

							if shouldMatchAllCPEs {
								// shouldMatchAllCPEs が true の場合、次のCPEMatchをチェック
								continue CPEMatchLoop
							}

							if shouldMatchAllNodes {
								// shouldMatchAllNodesかつshouldMatchAllCPEsがfalseの場合、1つマッチした時点で次のNodeをチェック
								continue NodeLoop
							}

							// すべてのオペレーターがORであるため、1つマッチした時点で該当と判断する
							goto matched
						} else {
							if shouldMatchAllCPEs {
								// shouldMatchAllCPEs が true の場合、1つでもマッチしなければ該当しないため次のProductをチェック
								continue ProductLoop
							}
						}
					}

					// ここに到達する場合は...
					if shouldMatchAllNodes {
						// shouldMatchAllNodesである場合、すべてのCPEMatchがマッチしなかった（＝条件を満たさないNodeが存在した）ということなので次のProductをチェック
						continue ProductLoop
					} else if shouldMatchAllCPEs {
						// shouldMatchAllCPEsである場合、すべてのCPEMatchがマッチしたということなのでマッチしたと判断
						goto matched
					}
				}

				if shouldMatchAllNodes {
					// ここに到達する場合、すべてのNodeがマッチしたということなのでマッチしたと判断
					goto matched
				}
			}
		}

		continue

	matched:
		fmt.Printf("\nCVE ID: %s\n", item.CVE.ID)
		fmt.Printf("  Matched Product UUID: %s\n", matchedProduct)

		// 英語の説明を探して表示
		var enDesc string
		for _, desc := range item.CVE.Descriptions {
			if desc.Lang == "en" {
				enDesc = desc.Value
				break
			}
		}

		if enDesc != "" {
			// 説明が長いので、最初の100文字だけ表示
			if len(enDesc) > 100 {
				fmt.Printf("  Description (en): %s...\n", enDesc[:100])
			} else {
				fmt.Printf("  Description (en): %s\n", enDesc)
			}
		} else {
			fmt.Println("  No English description found.")
		}

		// スコアを取得。該当しないバージョンは0にする
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

		dbVuln := db.Vulnerability{
			CVE:         item.CVE.ID,
			PublishedAt: item.CVE.Published.Time,
			Description: enDesc,
			CVSS40:      toPtr(cvss40),
			CVSS31:      toPtr(cvss31),
			CVSS30:      toPtr(cvss30),
			CVSS20:      toPtr(cvss20),
			ProductID:   uuid.MustParse(matchedProduct),
		}

		dbVulnerabilities = append(dbVulnerabilities, dbVuln)
	}

	return &dbVulnerabilities, nil
}
