/*
型定義

*/

/** 攻撃元区分 (Attack Vector) */
export const CvssAttackVector = {
    Network: "NETWORK",
    AdjacentNetwork: "ADJACENT_NETWORK",
    Local: "LOCAL",
    Physical: "PHYSICAL",
} as const;
export type CvssAttackVector = (typeof CvssAttackVector)[keyof typeof CvssAttackVector];

/** 攻撃条件の複雑さ (Attack Complexity) */
export const CvssAttackComplexity = {
    Low: "LOW",
    High: "HIGH",
} as const;
export type CvssAttackComplexity = (typeof CvssAttackComplexity)[keyof typeof CvssAttackComplexity];

/** 必要な特権レベル (Privileges Required) */
export const CvssPrivilegesRequired = {
    None: "NONE",
    Low: "LOW",
    High: "HIGH",
} as const;
export type CvssPrivilegesRequired = (typeof CvssPrivilegesRequired)[keyof typeof CvssPrivilegesRequired];

/** 影響のレベル (Confidentiality/Integrity/Availability Impact) */
export const CvssImpact = {
    High: "HIGH",
    Low: "LOW",
    None: "NONE",
} as const;
export type CvssImpact = (typeof CvssImpact)[keyof typeof CvssImpact];

/** 重大度 (Severity) */
export const CvssSeverity = {
    None: "NONE",
    Low: "LOW",
    Medium: "MEDIUM",
    High: "HIGH",
    Critical: "CRITICAL",
} as const;
export type CvssSeverity = (typeof CvssSeverity)[keyof typeof CvssSeverity];

// --- CVSS V3.1 のみ ---

/** ユーザ関与レベル (User Interaction) */
export const CvssV31UserInteraction = {
    None: "NONE",
    Required: "REQUIRED",
} as const;
export type CvssV31UserInteraction = (typeof CvssV31UserInteraction)[keyof typeof CvssV31UserInteraction];

/** スコープ (Scope) */
export const CvssScope = {
    Unchanged: "UNCHANGED",
    Changed: "CHANGED",
} as const;
export type CvssScope = (typeof CvssScope)[keyof typeof CvssScope];

// --- CVSS V4.0 のみ ---

/** 攻撃要件 (Attack Requirements) */
export const CvssAttackRequirements = {
    None: "NONE",
    Present: "PRESENT",
} as const;
export type CvssAttackRequirements = (typeof CvssAttackRequirements)[keyof typeof CvssAttackRequirements];

/** ユーザ関与レベル (User Interaction) */
export const CvssV4UserInteraction = {
    None: "NONE",
    Passive: "PASSIVE",
    Active: "ACTIVE",
} as const;
export type CvssV4UserInteraction = (typeof CvssV4UserInteraction)[keyof typeof CvssV4UserInteraction];

/** 悪用可能性の成熟度 (Exploit Maturity) - 脅威メトリクス */
export const CvssExploitMaturity = {
    NotDefined: "NOT_DEFINED",
    Unproven: "UNPROVEN",
    ProofOfConcept: "PROOF_OF_CONCEPT",
    High: "HIGH",
} as const;

// V4.0の vectorString で 'X' も使われるため (NOT_DEFINED と同義)
export type CvssExploitMaturity = (typeof CvssExploitMaturity)[keyof typeof CvssExploitMaturity] | "X";

// --- CVSS V4.0 補足メトリクス (Supplemental Metrics) ---

/** 安全性 (Safety) */
export const CvssSafety = {
    NotDefined: "NOT_DEFINED",
    Present: "PRESENT",
    Negligible: "NEGLIGIBLE",
} as const;
export type CvssSafety = (typeof CvssSafety)[keyof typeof CvssSafety] | "X";

/** 自動化可能性 (Automatable) */
export const CvssAutomatable = {
    NotDefined: "NOT_DEFINED",
    No: "NO",
    Yes: "YES",
} as const;
export type CvssAutomatable = (typeof CvssAutomatable)[keyof typeof CvssAutomatable] | "X";

/** 回復性 (Recovery) */
export const CvssRecovery = {
    NotDefined: "NOT_DEFINED",
    Automatic: "AUTOMATIC",
    User: "USER",
    Irrecoverable: "IRRECOVERABLE",
} as const;
export type CvssRecovery = (typeof CvssRecovery)[keyof typeof CvssRecovery] | "X";

/** 価値密度 (Value Density) */
export const CvssValueDensity = {
    NotDefined: "NOT_DEFINED",
    Diffuse: "DIFFUSE",
    Concentrated: "CONCENTRATED",
} as const;
export type CvssValueDensity = (typeof CvssValueDensity)[keyof typeof CvssValueDensity] | "X";

/** 脆弱性対応の労力 (Vulnerability Response Effort) */
export const CvssVulnerabilityResponseEffort = {
    NotDefined: "NOT_DEFINED",
    Low: "LOW",
    Moderate: "MODERATE",
    High: "HIGH",
} as const;
export type CvssVulnerabilityResponseEffort = (typeof CvssVulnerabilityResponseEffort)[keyof typeof CvssVulnerabilityResponseEffort] | "X";

/** 提供者の緊急性 (Provider Urgency) */
export const CvssProviderUrgency = {
    NotDefined: "NOT_DEFINED",
    Clear: "CLEAR",
    Green: "GREEN",
    Amber: "AMBER",
    Red: "RED",
} as const;
export type CvssProviderUrgency = (typeof CvssProviderUrgency)[keyof typeof CvssProviderUrgency] | "X";

// --- CVSS V2 のみ ---

/** 攻撃元区分 (Access Vector) */
export const CvssV2AccessVector = {
    Network: "NETWORK",
    AdjacentNetwork: "ADJACENT_NETWORK",
    Local: "LOCAL",
} as const;
export type CvssV2AccessVector = (typeof CvssV2AccessVector)[keyof typeof CvssV2AccessVector];

/** 攻撃条件の複雑さ (Access Complexity) */
export const CvssV2AccessComplexity = {
    Low: "LOW",
    Medium: "MEDIUM",
    High: "HIGH",
} as const;
export type CvssV2AccessComplexity = (typeof CvssV2AccessComplexity)[keyof typeof CvssV2AccessComplexity];

/** 認証要否 (Authentication) */
export const CvssV2Authentication = {
    None: "NONE",
    Single: "SINGLE",
    Multiple: "MULTIPLE",
} as const;
export type CvssV2Authentication = (typeof CvssV2Authentication)[keyof typeof CvssV2Authentication];

/** 影響のレベル (V2 Impact) */
export const CvssV2Impact = {
    Partial: "PARTIAL",
    Complete: "COMPLETE",
    None: "NONE",
} as const;
export type CvssV2Impact = (typeof CvssV2Impact)[keyof typeof CvssV2Impact];

// --- NVDレスポンス内のその他の固定値 ---

/** ソースのタイプ (Primary/Secondary) */
export const CveSourceType = {
    Primary: "Primary",
    Secondary: "Secondary",
} as const;
export type CveSourceType = (typeof CveSourceType)[keyof typeof CveSourceType];

/** CPE設定の論理演算子 */
export const CpeOperator = {
    Or: "OR",
    And: "AND",
} as const;
export type CpeOperator = (typeof CpeOperator)[keyof typeof CpeOperator];

// --- 共通ヘルパー型 ---

/** V4.0の未定義値 ('NOT_DEFINED' または 'X') */
export type CvssV4NotDef = "NOT_DEFINED" | "X";

/** CVSS V4.0のメトリクス（未定義許容）を表現するためのヘルパー型 */
export type CvssV4Metric<T> = T | CvssV4NotDef;

/** 多言語対応の文字列 (Description と WeaknessDescription で共通) */
export type LocalizedString = {
    lang: string;
    value: string;
};

/**
 * CVSSメトリクスの共通ベース構造
 * @template TData cvssDataフィールドの型 (CvssDataV40, CvssDataV31, CvssDataV2)
 */
export type CvssMetricBase<TData> = {
    source: string;
    type: CveSourceType;
    cvssData: TData;
};

// --- レスポンス全体の型定義 ---

// レスポンス全体のルート型
export type NvdCveResponse = {
    resultsPerPage: number;
    startIndex: number;
    totalResults: number;
    format: "NVD_CVE";
    version: "2.0";
    timestamp: string;
    vulnerabilities: Vulnerability[];
};

export type Vulnerability = {
    cve: Cve;
};

export type Cve = {
    id: string;
    sourceIdentifier: string;
    published: string;
    lastModified: string;
    vulnStatus: string;
    // cveTags: any[];
    descriptions: LocalizedString[];
    metrics: Metrics;
    weaknesses: Weakness[];
    configurations: Configuration[];
    references: Reference[];
};

export type Metrics = {
    cvssMetricV40?: CvssMetricV40[];
    cvssMetricV31?: CvssMetricV31[];
    cvssMetricV2?: CvssMetricV2[];
};

// CVSS Metric V4.0
export type CvssMetricV40 = CvssMetricBase<CvssDataV40>;

export type CvssDataV40 = {
    version: "4.0";
    vectorString: string;
    baseScore: number;
    baseSeverity: CvssSeverity;

    // --- ベースメトリクス (Base Metrics) ---
    attackVector: CvssV4Metric<CvssAttackVector>;
    attackComplexity: CvssV4Metric<CvssAttackComplexity>;
    attackRequirements: CvssV4Metric<CvssAttackRequirements>;
    privilegesRequired: CvssV4Metric<CvssPrivilegesRequired>;
    userInteraction: CvssV4Metric<CvssV4UserInteraction>;
    // 脆弱システムへの影響 (Vulnerable System Impacts)
    vulnConfidentialityImpact: CvssV4Metric<CvssImpact>;
    vulnIntegrityImpact: CvssV4Metric<CvssImpact>;
    vulnAvailabilityImpact: CvssV4Metric<CvssImpact>;
    // 後続システムへの影響 (Subsequent System Impacts)
    subConfidentialityImpact: CvssV4Metric<CvssImpact>;
    subIntegrityImpact: CvssV4Metric<CvssImpact>;
    subAvailabilityImpact: CvssV4Metric<CvssImpact>;

    // --- 脅威メトリクス (Threat Metrics) ---
    exploitMaturity: CvssExploitMaturity;

    // --- 補足メトリクス (Supplemental Metrics) ---
    safety: CvssV4Metric<CvssSafety>;
    automatable: CvssV4Metric<CvssAutomatable>;
    recovery: CvssV4Metric<CvssRecovery>;
    valueDensity: CvssV4Metric<CvssValueDensity>;
    vulnerabilityResponseEffort: CvssV4Metric<CvssVulnerabilityResponseEffort>;
    providerUrgency: CvssV4Metric<CvssProviderUrgency>;
};

// CVSS Metric V3.1
export type CvssMetricV31 = CvssMetricBase<CvssDataV31> & {
    exploitabilityScore: number;
    impactScore: number;
};

export type CvssDataV31 = {
    version: "3.1";
    vectorString: string;
    baseScore: number;
    baseSeverity: CvssSeverity;
    attackVector: CvssAttackVector;
    attackComplexity: CvssAttackComplexity;
    privilegesRequired: CvssPrivilegesRequired;
    userInteraction: CvssV31UserInteraction;
    scope: CvssScope;
    confidentialityImpact: CvssImpact;
    integrityImpact: CvssImpact;
    availabilityImpact: CvssImpact;
};

// CVSS Metric V2
export type CvssMetricV2 = CvssMetricBase<CvssDataV2> & {
    baseSeverity: CvssSeverity; // V2の重大度は Low, Medium, High のみ
    exploitabilityScore: number;
    impactScore: number;
    acInsufInfo: boolean;
    obtainAllPrivilege: boolean;
    obtainUserPrivilege: boolean;
    obtainOtherPrivilege: boolean;
    userInteractionRequired: boolean;
};

export type CvssDataV2 = {
    version: "2.0";
    vectorString: string;
    baseScore: number;
    accessVector: CvssV2AccessVector;
    accessComplexity: CvssV2AccessComplexity;
    authentication: CvssV2Authentication;
    confidentialityImpact: CvssV2Impact;
    integrityImpact: CvssV2Impact;
    availabilityImpact: CvssV2Impact;
};

export type Weakness = {
    source: string;
    type: CveSourceType;
    description: LocalizedString[];
};

export type Configuration = {
    nodes: Node[];
};

export type Node = {
    operator: CpeOperator;
    negate: boolean;
    cpeMatch: CpeMatch[];
};

export type CpeMatch = {
    vulnerable: boolean;
    criteria: string;
    matchCriteriaId: string;
};

export type Reference = {
    url: string;
    source: string;
    tags?: string[];
};
