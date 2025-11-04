package nvd

import (
	"strings"
	"time"
)

type NVRTime struct {
	time.Time
}

func (ct *NVRTime) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), "\"")
	if s == "null" {
		return nil
	}

	// 複数のフォーマットを試行
	formats := []string{
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05.999999999Z",
		"2006-01-02T15:04:05Z",
		time.RFC3339,
		time.RFC3339Nano,
	}

	var err error
	for _, format := range formats {
		t, parseErr := time.Parse(format, s)
		if parseErr == nil {
			ct.Time = t
			return nil
		}
		err = parseErr
	}
	return err
}

type APIResponse struct {
	ResultsPerPage  int                 `json:"resultsPerPage"`
	StartIndex      int                 `json:"startIndex"`
	TotalResults    int                 `json:"totalResults"`
	Format          string              `json:"format"`
	Version         string              `json:"version"`
	Timestamp       NVRTime             `json:"timestamp"`
	Vulnerabilities []VulnerabilityItem `json:"vulnerabilities"`
}

type VulnerabilityItem struct {
	CVE CVE `json:"cve"`
}

type CVE struct {
	ID               string  `json:"id"`
	SourceIdentifier string  `json:"sourceIdentifier"`
	Published        NVRTime `json:"published"`
	LastModified     NVRTime `json:"lastModified"`
	VulnStatus       string  `json:"vulnStatus"`
	//CveTags          []string        `json:"cveTags"`
	Descriptions   []Description   `json:"descriptions"`
	Metrics        Metrics         `json:"metrics"`
	Weaknesses     []Weakness      `json:"weaknesses"`
	Configurations []Configuration `json:"configurations"`
	References     []Reference     `json:"references"`
}

type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Metrics struct {
	CVSSMetricV40 []CVSSMetricV40 `json:"cvssMetricV40,omitempty"`
	CVSSMetricV31 []CVSSMetricV31 `json:"cvssMetricV31,omitempty"`
	CVSSMetricV2  []CVSSMetricV2  `json:"cvssMetricV2,omitempty"`
}

type CVSSMetricV31 struct {
	Source              string      `json:"source"`
	Type                string      `json:"type"`
	CVSSData            CVSSDataV31 `json:"cvssData"`
	ExploitabilityScore float64     `json:"exploitabilityScore"`
	ImpactScore         float64     `json:"impactScore"`
}

// CVSSMetricV40 と CVSSDataV40 は NVD の cvssMetricV40 をパースするための型です
type CVSSMetricV40 struct {
	Source   string      `json:"source"`
	Type     string      `json:"type"`
	CVSSData CVSSDataV40 `json:"cvssData"`
}

type CVSSDataV40 struct {
	Version                           string  `json:"version"`
	VectorString                      string  `json:"vectorString"`
	BaseScore                         float64 `json:"baseScore"`
	BaseSeverity                      string  `json:"baseSeverity"`
	AttackVector                      string  `json:"attackVector"`
	AttackComplexity                  string  `json:"attackComplexity"`
	AttackRequirements                string  `json:"attackRequirements"`
	PrivilegesRequired                string  `json:"privilegesRequired"`
	UserInteraction                   string  `json:"userInteraction"`
	VulnConfidentialityImpact         string  `json:"vulnConfidentialityImpact"`
	VulnIntegrityImpact               string  `json:"vulnIntegrityImpact"`
	VulnAvailabilityImpact            string  `json:"vulnAvailabilityImpact"`
	SubConfidentialityImpact          string  `json:"subConfidentialityImpact"`
	SubIntegrityImpact                string  `json:"subIntegrityImpact"`
	SubAvailabilityImpact             string  `json:"subAvailabilityImpact"`
	ExploitMaturity                   string  `json:"exploitMaturity"`
	ConfidentialityRequirement        string  `json:"confidentialityRequirement"`
	IntegrityRequirement              string  `json:"integrityRequirement"`
	AvailabilityRequirement           string  `json:"availabilityRequirement"`
	ModifiedAttackVector              string  `json:"modifiedAttackVector"`
	ModifiedAttackComplexity          string  `json:"modifiedAttackComplexity"`
	ModifiedAttackRequirements        string  `json:"modifiedAttackRequirements"`
	ModifiedPrivilegesRequired        string  `json:"modifiedPrivilegesRequired"`
	ModifiedUserInteraction           string  `json:"modifiedUserInteraction"`
	ModifiedVulnConfidentialityImpact string  `json:"modifiedVulnConfidentialityImpact"`
	ModifiedVulnIntegrityImpact       string  `json:"modifiedVulnIntegrityImpact"`
	ModifiedVulnAvailabilityImpact    string  `json:"modifiedVulnAvailabilityImpact"`
	ModifiedSubConfidentialityImpact  string  `json:"modifiedSubConfidentialityImpact"`
	ModifiedSubIntegrityImpact        string  `json:"modifiedSubIntegrityImpact"`
	ModifiedSubAvailabilityImpact     string  `json:"modifiedSubAvailabilityImpact"`
	Safety                            string  `json:"Safety"`
	Automatable                       string  `json:"Automatable"`
	Recovery                          string  `json:"Recovery"`
	ValueDensity                      string  `json:"valueDensity"`
	VulnerabilityResponseEffort       string  `json:"vulnerabilityResponseEffort"`
	ProviderUrgency                   string  `json:"providerUrgency"`
}

// CVSSMetricV2 と CVSSDataV20 は NVD の cvssMetricV2 をパースするための型です
type CVSSMetricV2 struct {
	Source                  string      `json:"source"`
	Type                    string      `json:"type"`
	CVSSData                CVSSDataV20 `json:"cvssData"`
	BaseSeverity            string      `json:"baseSeverity,omitempty"`
	ExploitabilityScore     float64     `json:"exploitabilityScore,omitempty"`
	ImpactScore             float64     `json:"impactScore,omitempty"`
	AcInsufInfo             bool        `json:"acInsufInfo,omitempty"`
	ObtainAllPrivilege      bool        `json:"obtainAllPrivilege,omitempty"`
	ObtainUserPrivilege     bool        `json:"obtainUserPrivilege,omitempty"`
	ObtainOtherPrivilege    bool        `json:"obtainOtherPrivilege,omitempty"`
	UserInteractionRequired bool        `json:"userInteractionRequired,omitempty"`
}

type CVSSDataV20 struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	BaseScore             float64 `json:"baseScore"`
	AccessVector          string  `json:"accessVector"`
	AccessComplexity      string  `json:"accessComplexity"`
	Authentication        string  `json:"authentication"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
}

type CVSSDataV31 struct {
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
	Operator string `json:"operator,omitempty"`
	Nodes    []Node `json:"nodes"`
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
