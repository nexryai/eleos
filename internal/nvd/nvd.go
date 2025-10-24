package nvd

import "time"

type APIResponse struct {
	ResultsPerPage  int                 `json:"resultsPerPage"`
	StartIndex      int                 `json:"startIndex"`
	TotalResults    int                 `json:"totalResults"`
	Format          string              `json:"format"`
	Version         string              `json:"version"`
	Timestamp       time.Time           `json:"timestamp"`
	Vulnerabilities []VulnerabilityItem `json:"vulnerabilities"`
}

type VulnerabilityItem struct {
	CVE CVE `json:"cve"`
}

type CVE struct {
	ID               string          `json:"id"`
	SourceIdentifier string          `json:"sourceIdentifier"`
	Published        time.Time       `json:"published"`
	LastModified     time.Time       `json:"lastModified"`
	VulnStatus       string          `json:"vulnStatus"`
	CveTags          []string        `json:"cveTags"`
	Descriptions     []Description   `json:"descriptions"`
	Metrics          Metrics         `json:"metrics"`
	Weaknesses       []Weakness      `json:"weaknesses"`
	Configurations   []Configuration `json:"configurations"`
	References       []Reference     `json:"references"`
}

type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Metrics struct {
	CVSSMetricV31 []CVSSMetricV31 `json:"cvssMetricV31"`
}

type CVSSMetricV31 struct {
	Source              string   `json:"source"`
	Type                string   `json:"type"`
	CVSSData            CVSSData `json:"cvssData"`
	ExploitabilityScore float64  `json:"exploitabilityScore"`
	ImpactScore         float64  `json:"impactScore"`
}

type CVSSData struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	AttackVector          string  `json:"attackVector"`
	AttackComplexity      string  `json:"attackComplexity"`
	PrivilegesRequired    string  `json:"privilegesRequired"`
	UserInteraction       string  `json:"userInteraction"`
	Scope                 string  `json:"scope"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float64 `json:"baseScore"`
	BaseSeverity          string  `json:"baseSeverity"`
}

type Weakness struct {
	Source      string        `json:"source"`
	Type        string        `json:"type"`
	Description []Description `json:"description"`
}

type Configuration struct {
	Nodes []Node `json:"nodes"`
}

type Node struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate"`
	CPEMatch []CPEMatch `json:"cpeMatch"`
}

type CPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
	MatchCriteriaID       string `json:"matchCriteriaId"`
}

type Reference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags,omitempty"` 
}
