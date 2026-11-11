import type {
  AgentKeyPosture,
  ApprovalRequest,
  AuditLogEntry,
  BlocklistEntry,
  CounterpartyEvaluationResponse,
  NetworkId,
  PolicyConfig,
  SignedTxArtifact,
} from "../guard/types.js";

export type {
  AgentKeyPosture,
  ApprovalRequest,
  AuditLogEntry,
  BlocklistEntry,
  CounterpartyEvaluationResponse,
  NetworkId,
  PolicyConfig,
  SignedTxArtifact,
};

export interface PaymentResponse {
  status: "executed" | "pending_approval" | "blocked" | "key_scope_rejected";
  evaluation?: CounterpartyEvaluationResponse;
  artifact?: SignedTxArtifact;
  approval?: ApprovalRequest;
  auditEntry: AuditLogEntry;
  reason?: string;
}

export interface DemoSuiteResponse {
  title: string;
  steps: Array<{
    scenario: string;
    result: PaymentResponse;
  }>;
}
