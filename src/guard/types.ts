import { z } from "zod";

export const NetworkSchema = z.enum(["testnet", "mainnet"]);
export type NetworkId = z.infer<typeof NetworkSchema>;

export const VerdictSchema = z.enum(["ALLOW", "WARN", "BLOCK"]);
export type Verdict = z.infer<typeof VerdictSchema>;

export const SignalStatusSchema = z.enum(["pass", "caution", "danger", "unavailable"]);
export type SignalStatus = z.infer<typeof SignalStatusSchema>;

export const SignalCategorySchema = z.enum([
  "identity",
  "age_activity",
  "contract_code",
  "key_posture",
  "prior_history",
  "blocklist",
  "policy_budget",
  "prompt_security",
]);
export type SignalCategory = z.infer<typeof SignalCategorySchema>;

export interface RiskSignal {
  id: string;
  name: string;
  category: SignalCategory;
  status: SignalStatus;
  scoreImpact: number;
  summary: string;
  source: string;
  details?: Record<string, unknown>;
}

export const EvaluateRequestSchema = z.object({
  network: NetworkSchema.default("testnet"),
  agentId: z.string().min(2).max(64).default("treasury-agent.testnet"),
  receiverId: z.string().min(1).max(128),
  amountNear: z.number().nonnegative().max(1_000_000),
  methodName: z.string().max(128).optional(),
  instruction: z.string().max(4000).optional(),
  memo: z.string().max(1000).optional(),
  targetContractId: z.string().max(128).optional(),
  attachedDepositNear: z.number().nonnegative().optional(),
});

export type EvaluateRequest = z.infer<typeof EvaluateRequestSchema>;

export const AgentPaymentRequestSchema = EvaluateRequestSchema.extend({
  intentId: z.string().max(128).optional(),
  bypassGuardSimulation: z.boolean().optional(),
  directTransferSimulation: z.boolean().optional(),
});

export type AgentPaymentRequest = z.infer<typeof AgentPaymentRequestSchema>;

export const EvidenceSchema = z.object({
  txHash: z.string().max(128).optional(),
  contractCodeHash: z.string().max(128).optional(),
  calldataSnippet: z.string().max(1000).optional(),
  notes: z.string().min(8).max(2000),
  observedAt: z.string().optional(),
});

export const BlocklistCreateSchema = z.object({
  accountId: z.string().min(2).max(128),
  network: NetworkSchema.default("testnet"),
  category: z.enum([
    "drainer",
    "prompt_injection",
    "phishing",
    "rug_upgrade",
    "compromised_key",
    "malicious_contract",
  ]),
  reason: z.string().min(5).max(500),
  reportedBy: z.string().min(2).max(128).default("sentinel-agent.testnet"),
  evidence: EvidenceSchema,
});

export type BlocklistCreateInput = z.infer<typeof BlocklistCreateSchema>;

export interface BlocklistEntry {
  id: string;
  accountId: string;
  network: NetworkId;
  category:
    | "drainer"
    | "prompt_injection"
    | "phishing"
    | "rug_upgrade"
    | "compromised_key"
    | "malicious_contract";
  reason: string;
  reportedBy: string;
  createdAt: string;
  evidence: {
    txHash?: string;
    contractCodeHash?: string;
    calldataSnippet?: string;
    notes: string;
    observedAt: string;
  };
}

export const PolicyUpdateSchema = z.object({
  maxPerTxNear: z.number().positive().max(100_000).optional(),
  dailySpendCapNear: z.number().positive().max(1_000_000).optional(),
  minAccountAgeDays: z.number().nonnegative().max(3650).optional(),
  warnOnContractCodeChangeHours: z.number().nonnegative().max(8760).optional(),
  requirePriorInteraction: z.boolean().optional(),
  allowUnregisteredReceivers: z.boolean().optional(),
  warnScoreThreshold: z.number().min(1).max(99).optional(),
  blockScoreThreshold: z.number().min(10).max(100).optional(),
  blockedMethods: z.array(z.string().min(1).max(128)).optional(),
  allowlistedReceivers: z.array(z.string().min(2).max(128)).optional(),
  allowedContracts: z.array(z.string().min(2).max(128)).optional(),
});

export interface PolicyConfig {
  maxPerTxNear: number;
  dailySpendCapNear: number;
  minAccountAgeDays: number;
  warnOnContractCodeChangeHours: number;
  requirePriorInteraction: boolean;
  allowUnregisteredReceivers: boolean;
  warnScoreThreshold: number;
  blockScoreThreshold: number;
  blockedMethods: string[];
  allowlistedReceivers: string[];
  allowedContracts: string[];
}

export interface NearOnChainSnapshot {
  network: NetworkId;
  accountId: string;
  validAccountIdFormat: boolean;
  exists: boolean | null;
  rpcAvailable: boolean;
  rpcEndpoint: string;
  rpcError?: string;
  balanceNear: string | null;
  availableNear: string | null;
  stakedNear: string | null;
  storageBytes: number | null;
  hasContract: boolean | null;
  codeHash: string | null;
  fullAccessKeyCount: number | null;
  functionCallKeyCount: number | null;
  locked: boolean | null;
  indexerAvailable: boolean;
  indexerError?: string;
  createdAtIso: string | null;
  createdTxHash: string | null;
  accountAgeDays: number | null;
  recentTxCount: number | null;
  recentSuccessRate: number | null;
  recentDeployContractAt: string | null;
  recentDeployContractTx: string | null;
  hoursSinceLastCodeDeploy: number | null;
  priorInteractionsWithAgent: number | null;
  priorInteractionSampleTx: string | null;
  fastNearAvailable: boolean;
  fastNearTokenCount: number | null;
  codeHashChangedFromSnapshot: boolean;
  previousSnapshotCodeHash: string | null;
}

export interface InjectionAnalysis {
  detected: boolean;
  severity: "none" | "suspicious" | "critical";
  scoreImpact: number;
  matchedRules: Array<{ id: string; label: string; excerpt: string }>;
  mentionedOtherAccounts: string[];
  aiAnalysis?: {
    used: boolean;
    provider: string;
    model?: string;
    chatId?: string;
    verdict?: "SAFE" | "SUSPICIOUS" | "INJECTION";
    explanation?: string;
    error?: string;
  };
}

export interface CounterpartyEvaluationResponse {
  evaluationId: string;
  verdict: Verdict;
  riskScore: number;
  hardBlocked: boolean;
  reasons: string[];
  signals: RiskSignal[];
  onChain: NearOnChainSnapshot;
  injection: InjectionAnalysis;
  policySummary: {
    maxPerTxNear: number;
    dailySpendCapNear: number;
    dailySpentBeforeNear: number;
    dailyRemainingNear: number;
  };
  evaluatedAt: string;
}

export interface SignedTxArtifact {
  mode: "live_testnet_broadcast" | "local_borsh_function_call";
  signerAccountId: string;
  publicKey: string;
  permissionType: "FunctionCall";
  scopedContractId: string;
  methodName: string;
  argsJson: string;
  attachedDepositYocto: string;
  gasUnits: string;
  txHash: string;
  blockHash: string;
  signatureBase58: string;
  serializedBytesLength: number;
  signatureVerifiedLocally: boolean;
  rpcBroadcastHash?: string;
  rpcError?: string;
}

export interface ApprovalRequest {
  id: string;
  createdAt: string;
  updatedAt: string;
  status: "pending" | "approved" | "rejected";
  reviewer?: string;
  reviewerNote?: string;
  request: AgentPaymentRequest;
  evaluation: CounterpartyEvaluationResponse;
  executionArtifact?: SignedTxArtifact;
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  action:
    | "evaluate"
    | "payment_executed"
    | "payment_pending_approval"
    | "payment_blocked"
    | "key_scope_rejected"
    | "human_approved"
    | "human_rejected"
    | "blocklist_reported"
    | "policy_updated";
  network: NetworkId;
  agentId: string;
  receiverId: string;
  amountNear?: number;
  verdict?: Verdict;
  riskScore?: number;
  reasons: string[];
  txHash?: string;
  approvalId?: string;
  details?: Record<string, unknown>;
}

export interface CodeHashSnapshot {
  accountId: string;
  network: NetworkId;
  codeHash: string;
  firstSeenAt: string;
  lastSeenAt: string;
}

export interface AgentKeyPosture {
  agentAccountId: string;
  network: NetworkId;
  publicKey: string;
  mode: "live_testnet" | "local_function_call_verifier";
  permissionType: "FunctionCall" | "FullAccess";
  scopedContractId: string;
  allowedMethodNames: string[];
  allowanceNear: string;
  allowanceRemainingNear: string;
  fullAccessKeysCount: number;
  nativeTransferAllowedByKey: false;
  attachedDepositAllowedByKey: false;
  onChainVerified: boolean;
  onChainVerifyNote: string;
  dailySpentNear: number;
  dailySpendCapNear: number;
}
