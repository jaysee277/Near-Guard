import { Amount, Near, generateKey, parseAmount, parseKey, type KeyPair } from "near-kit";
import type { NearDataFetcher } from "./nearClient.js";
import { buildAndSignFunctionCallTx } from "./nearTx.js";
import type { CounterpartyRiskService } from "./riskScorer.js";
import type { NearGuardStore } from "./store.js";
import type {
  AgentKeyPosture,
  AgentPaymentRequest,
  ApprovalRequest,
  AuditLogEntry,
  CounterpartyEvaluationResponse,
  NetworkId,
  SignedTxArtifact,
} from "./types.js";

export class FullAccessKeyRejectedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FullAccessKeyRejectedError";
  }
}

export class FunctionCallScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FunctionCallScopeError";
  }
}

export interface AgentWalletConfig {
  agentAccountId?: string;
  network?: NetworkId;
  scopedContractId?: string;
  allowedMethodNames?: string[];
  allowanceNear?: number;
  functionCallPrivateKey?: string;
}

export type PaymentExecutionResult =
  | {
      status: "executed";
      evaluation: CounterpartyEvaluationResponse;
      artifact: SignedTxArtifact;
      auditEntry: AuditLogEntry;
    }
  | {
      status: "pending_approval";
      evaluation: CounterpartyEvaluationResponse;
      approval: ApprovalRequest;
      auditEntry: AuditLogEntry;
    }
  | {
      status: "blocked";
      evaluation: CounterpartyEvaluationResponse;
      auditEntry: AuditLogEntry;
      reason: string;
    }
  | {
      status: "key_scope_rejected";
      evaluation?: CounterpartyEvaluationResponse;
      auditEntry: AuditLogEntry;
      reason: string;
    };

export class AgentGuardWallet {
  private readonly store: NearGuardStore;
  private readonly fetcher: NearDataFetcher;
  private readonly riskService: CounterpartyRiskService;
  private readonly keyPair: KeyPair;
  private readonly liveKeyConfigured: boolean;

  readonly agentAccountId: string;
  readonly network: NetworkId;
  readonly scopedContractId: string;
  readonly allowedMethodNames: string[];
  private allowanceRemainingNear: number;
  private readonly initialAllowanceNear: number;
  private localNonce = 1n;
  private fullAccessDetectedOnChain = false;
  private onChainVerifyNote = "Local Function-Call Key verifier (no FullAccess key held by agent).";

  constructor(
    store: NearGuardStore,
    fetcher: NearDataFetcher,
    riskService: CounterpartyRiskService,
    config: AgentWalletConfig = {},
  ) {
    this.store = store;
    this.fetcher = fetcher;
    this.riskService = riskService;

    this.network =
      config.network ??
      (process.env.NEAR_NETWORK === "mainnet" ? "mainnet" : "testnet");

    this.agentAccountId =
      config.agentAccountId ??
      (process.env.AGENT_ACCOUNT_ID?.trim() || "treasury-agent.testnet");

    this.scopedContractId =
      config.scopedContractId ??
      (process.env.SCOPED_CONTRACT_ID?.trim() || "guest-book.testnet");

    const envMethods = process.env.SCOPED_METHOD_NAMES?.split(",")
      .map((m) => m.trim())
      .filter(Boolean);

    this.allowedMethodNames =
      config.allowedMethodNames ??
      (envMethods && envMethods.length > 0
        ? envMethods
        : ["addMessage", "pay_counterparty", "route_payment"]);

    const parsedAllowance = Number(process.env.AGENT_KEY_ALLOWANCE_NEAR ?? "0.25");
    this.initialAllowanceNear =
      config.allowanceNear ??
      (Number.isFinite(parsedAllowance) && parsedAllowance > 0
        ? parsedAllowance
        : 0.25);
    this.allowanceRemainingNear = this.initialAllowanceNear;

    const envKey =
      config.functionCallPrivateKey ?? process.env.AGENT_FUNCTION_CALL_KEY?.trim();

    if (envKey) {
      this.keyPair = parseKey(envKey as `ed25519:${string}`);
      this.liveKeyConfigured = Boolean(process.env.AGENT_ACCOUNT_ID?.trim());
    } else {
      this.keyPair = generateKey();
      this.liveKeyConfigured = false;
    }
  }

  /**
   * Queries NEAR RPC when live credentials are configured to prove the agent key
   * is strictly FunctionCall-scoped and NEVER a FullAccess key.
   */
  async verifyKeyPosture(overrideNetwork?: NetworkId): Promise<AgentKeyPosture> {
    const net = overrideNetwork ?? this.network;
    const policy = this.store.getPolicy();
    let onChainVerified = false;
    let verifyNote =
      "Keypair restricted to FunctionCall scope in AgentGuardWallet (set AGENT_ACCOUNT_ID + AGENT_FUNCTION_CALL_KEY for live RPC check & broadcast).";
    let permissionType: "FunctionCall" | "FullAccess" = "FunctionCall";
    let fullAccessCount = 0;

    if (this.liveKeyConfigured) {
      const check = await this.fetcher.checkAccessKeyPermission(
        net,
        this.agentAccountId,
        this.keyPair.publicKey.toString(),
      );
      if (check.found) {
        if (check.permission === "FullAccess" || check.permission === "GasKeyFullAccess") {
          this.fullAccessDetectedOnChain = true;
          permissionType = "FullAccess";
          fullAccessCount = 1;
          verifyNote =
            "SECURITY VIOLATION: Configured key has FullAccess on-chain! Autonomous execution disabled.";
        } else {
          this.fullAccessDetectedOnChain = false;
          onChainVerified = true;
          verifyNote = `Verified on-chain via NEAR ${net} RPC view_access_key: FunctionCall permission only.`;
        }
      } else {
        verifyNote = `On-chain lookup note: ${check.reason}`;
      }
    }

    this.onChainVerifyNote = verifyNote;

    return {
      agentAccountId: this.agentAccountId,
      network: net,
      publicKey: this.keyPair.publicKey.toString(),
      mode: this.liveKeyConfigured && !this.fullAccessDetectedOnChain
        ? "live_testnet"
        : "local_function_call_verifier",
      permissionType,
      scopedContractId: this.scopedContractId,
      allowedMethodNames: this.allowedMethodNames,
      allowanceNear: this.initialAllowanceNear.toFixed(4),
      allowanceRemainingNear: Math.max(0, this.allowanceRemainingNear).toFixed(4),
      fullAccessKeysCount: fullAccessCount,
      nativeTransferAllowedByKey: false,
      attachedDepositAllowedByKey: false,
      onChainVerified,
      onChainVerifyNote: this.onChainVerifyNote,
      dailySpentNear: this.store.getDailySpentNear(this.agentAccountId, net),
      dailySpendCapNear: policy.dailySpendCapNear,
    };
  }

  /**
   * Simulates & enforces Layer 2 protocol boundaries of a NEAR Function-Call Access Key:
   * - Single receiver_id (`scopedContractId`)
   * - Allowed method_names list
   * - Cannot transfer NEAR directly or attach >0 NEAR deposit
   * - Stops immediately if key allowance is exhausted or FullAccess is detected
   */
  private assertFunctionCallKeyScope(params: {
    targetContractId: string;
    methodName: string;
    attachedDepositNear: number;
    directTransferSimulation?: boolean;
  }): void {
    if (this.fullAccessDetectedOnChain) {
      throw new FullAccessKeyRejectedError(
        "Refusing to sign: agent refuses FullAccess keys. Re-configure with a scoped FunctionCall access key.",
      );
    }

    if (params.directTransferSimulation) {
      throw new FunctionCallScopeError(
        `Protocol key-scope enforcement: Function-Call key cannot sign raw native NEAR Transfer actions (key is pinned to receiver_id="${this.scopedContractId}").`,
      );
    }

    if (params.targetContractId.toLowerCase() !== this.scopedContractId.toLowerCase()) {
      throw new FunctionCallScopeError(
        `Protocol key-scope enforcement: target contract "${params.targetContractId}" violates Function-Call key receiver_id="${this.scopedContractId}".`,
      );
    }

    if (
      this.allowedMethodNames.length > 0 &&
      !this.allowedMethodNames.includes(params.methodName)
    ) {
      throw new FunctionCallScopeError(
        `Protocol key-scope enforcement: method "${params.methodName}" is outside Function-Call key method_names=[${this.allowedMethodNames.join(", ")}].`,
      );
    }

    if (params.attachedDepositNear > 0) {
      throw new FunctionCallScopeError(
        `Protocol key-scope enforcement: Function-Call keys cannot attach NEAR token deposits (requested ${params.attachedDepositNear} NEAR). Payouts must route through vault/escrow methods with 0 attached NEAR.`,
      );
    }

    if (this.allowanceRemainingNear < 0.005) {
      throw new FunctionCallScopeError(
        "Function-Call key gas allowance exhausted (NotEnoughAllowance). Rotate/add a new Function-Call key using a human Full-Access key.",
      );
    }
  }

  private async signScopedTransaction(
    request: AgentPaymentRequest,
    methodName: string,
  ): Promise<SignedTxArtifact> {
    const args: Record<string, unknown> =
      this.scopedContractId === "guest-book.testnet" && methodName === "addMessage"
        ? {
            text: `[NEAR-GUARD] Verified agent payment intent ${request.amountNear} NEAR -> ${request.receiverId}${request.memo ? ` | ${request.memo}` : ""}`,
          }
        : {
            receiver_id: request.receiverId,
            amount_yocto: parseAmount(Amount.NEAR(request.amountNear)),
            memo: request.memo ?? request.instruction ?? "Agent payout",
          };

    const targetContract = request.targetContractId?.trim() || this.scopedContractId;
    const attachedDeposit = request.attachedDepositNear ?? 0;

    // Layer 2 verification BEFORE signing
    this.assertFunctionCallKeyScope({
      targetContractId: targetContract,
      methodName,
      attachedDepositNear: attachedDeposit,
      directTransferSimulation: request.directTransferSimulation,
    });

    // If live Testnet Function-Call key & account configured, verify on-chain key is not FullAccess first
    let rpcBroadcastHash: string | undefined;
    let rpcError: string | undefined;
    let mode: SignedTxArtifact["mode"] = "local_borsh_function_call";

    if (this.liveKeyConfigured && request.network === "testnet") {
      const posture = await this.verifyKeyPosture("testnet");
      if (posture.permissionType === "FullAccess") {
        throw new FullAccessKeyRejectedError(
          "Live RPC check detected FullAccess key! Refusing autonomous agent signing.",
        );
      }

      if (posture.onChainVerified) {
        try {
          const liveNear = new Near({
            network: "testnet",
            rpcUrl: "https://test.rpc.fastnear.com",
            privateKey: this.keyPair.secretKey as `ed25519:${string}`,
            defaultSignerId: this.agentAccountId,
          });
          const tx = liveNear
            .transaction(this.agentAccountId)
            .functionCall(targetContract, methodName, args, { gas: "30 Tgas" });
          const outcome = await tx.send({ waitUntil: "EXECUTED_OPTIMISTIC" });
          rpcBroadcastHash = outcome.transaction.hash;
          mode = "live_testnet_broadcast";
        } catch (err) {
          rpcError = err instanceof Error ? err.message : "Live Testnet broadcast failed";
        }
      }
    }

    const { blockHash } = await this.fetcher.fetchFinalBlockHash(request.network);
    const nonce = this.localNonce;
    this.localNonce += 1n;

    const built = buildAndSignFunctionCallTx({
      signerId: request.agentId || this.agentAccountId,
      receiverId: targetContract,
      methodName,
      args,
      gas: "30 Tgas",
      attachedDepositYocto: 0n,
      nonce,
      blockHashBase58: blockHash,
      keyPair: this.keyPair,
    });

    // Deduct estimated gas reserve (~0.0025 NEAR) from local FunctionCall allowance tracker
    this.allowanceRemainingNear = Math.max(
      0,
      Number((this.allowanceRemainingNear - 0.0025).toFixed(6)),
    );

    return {
      mode,
      signerAccountId: request.agentId || this.agentAccountId,
      publicKey: this.keyPair.publicKey.toString(),
      permissionType: "FunctionCall",
      scopedContractId: targetContract,
      methodName,
      argsJson: built.argsJson,
      attachedDepositYocto: "0",
      gasUnits: built.gasUnits,
      txHash: rpcBroadcastHash ?? built.txHash,
      blockHash,
      signatureBase58: built.signatureBase58,
      serializedBytesLength: built.serializedSignedTx.length,
      signatureVerifiedLocally: built.signatureVerified,
      rpcBroadcastHash,
      rpcError,
    };
  }

  /**
   * Primary entrypoint used by autonomous AI agents before paying a counterparty.
   */
  async requestPayment(rawRequest: AgentPaymentRequest): Promise<PaymentExecutionResult> {
    const request: AgentPaymentRequest = {
      ...rawRequest,
      agentId: (rawRequest.agentId || this.agentAccountId).toLowerCase().trim(),
      receiverId: rawRequest.receiverId.toLowerCase().trim(),
    };

    const chosenMethod =
      request.methodName?.trim() ||
      (this.scopedContractId === "guest-book.testnet" ? "addMessage" : "pay_counterparty");

    // Simulation flag for proving Layer 2 Function-Call Key defense even if Guard was skipped
    if (request.bypassGuardSimulation) {
      try {
        this.assertFunctionCallKeyScope({
          targetContractId: request.targetContractId?.trim() || request.receiverId,
          methodName: chosenMethod,
          attachedDepositNear: request.attachedDepositNear ?? 0,
          directTransferSimulation: request.directTransferSimulation ?? true,
        });
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Rejected by Function-Call key scope.";
        const auditEntry = this.store.appendAuditLog({
          action: "key_scope_rejected",
          network: request.network,
          agentId: request.agentId,
          receiverId: request.receiverId,
          amountNear: request.amountNear,
          verdict: "BLOCK",
          reasons: [msg],
        });
        return { status: "key_scope_rejected", auditEntry, reason: msg };
      }
    }

    // Layer 1: NEAR Guard Counterparty & Prompt-Injection Evaluation
    const evaluation = await this.riskService.evaluate(request);

    if (evaluation.verdict === "BLOCK") {
      const reason = `AgentGuardWallet refused to sign: ${evaluation.reasons[0] ?? "Blocked by NEAR Guard policy."}`;
      const auditEntry = this.store.appendAuditLog({
        action: "payment_blocked",
        network: request.network,
        agentId: request.agentId,
        receiverId: request.receiverId,
        amountNear: request.amountNear,
        verdict: "BLOCK",
        riskScore: evaluation.riskScore,
        reasons: evaluation.reasons,
      });
      return {
        status: "blocked",
        evaluation,
        auditEntry,
        reason,
      };
    }

    if (evaluation.verdict === "WARN") {
      const approval = this.store.createApprovalRequest(request, evaluation);
      const auditEntry = this.store.appendAuditLog({
        action: "payment_pending_approval",
        network: request.network,
        agentId: request.agentId,
        receiverId: request.receiverId,
        amountNear: request.amountNear,
        verdict: "WARN",
        riskScore: evaluation.riskScore,
        reasons: evaluation.reasons,
        approvalId: approval.id,
      });
      return {
        status: "pending_approval",
        evaluation,
        approval,
        auditEntry,
      };
    }

    // Verdict is ALLOW -> Verify Layer 2 key scope & sign scoped FunctionCall transaction
    try {
      const artifact = await this.signScopedTransaction(request, chosenMethod);
      this.store.recordSpend({
        network: request.network,
        agentId: request.agentId,
        receiverId: request.receiverId,
        amountNear: request.amountNear,
        txHash: artifact.txHash,
      });
      const auditEntry = this.store.appendAuditLog({
        action: "payment_executed",
        network: request.network,
        agentId: request.agentId,
        receiverId: request.receiverId,
        amountNear: request.amountNear,
        verdict: "ALLOW",
        riskScore: evaluation.riskScore,
        reasons: evaluation.reasons,
        txHash: artifact.txHash,
        details: {
          scopedContractId: artifact.scopedContractId,
          methodName: artifact.methodName,
          signatureVerifiedLocally: artifact.signatureVerifiedLocally,
        },
      });
      return {
        status: "executed",
        evaluation,
        artifact,
        auditEntry,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Key scope enforcement rejected tx.";
      const auditEntry = this.store.appendAuditLog({
        action: "key_scope_rejected",
        network: request.network,
        agentId: request.agentId,
        receiverId: request.receiverId,
        amountNear: request.amountNear,
        verdict: evaluation.verdict,
        riskScore: evaluation.riskScore,
        reasons: [msg],
      });
      return {
        status: "key_scope_rejected",
        evaluation,
        auditEntry,
        reason: msg,
      };
    }
  }

  async approvePending(
    approvalId: string,
    reviewer = "operator-human",
    note?: string,
  ): Promise<{ approval: ApprovalRequest; artifact: SignedTxArtifact; auditEntry: AuditLogEntry }> {
    const existing = this.store.getApproval(approvalId);
    if (!existing) {
      throw new Error(`Approval request "${approvalId}" not found.`);
    }
    if (existing.status !== "pending") {
      throw new Error(`Approval request "${approvalId}" is already ${existing.status}.`);
    }

    // Re-check current 24h cap before signing human-approved transaction
    const policy = this.store.getPolicy();
    const spent = this.store.getDailySpentNear(
      existing.request.agentId,
      existing.request.network,
    );
    if (spent + existing.request.amountNear > policy.dailySpendCapNear) {
      throw new Error(
        `Cannot approve: projected 24h spend (${spent + existing.request.amountNear} NEAR) now exceeds daily cap (${policy.dailySpendCapNear} NEAR).`,
      );
    }

    const chosenMethod =
      existing.request.methodName?.trim() ||
      (this.scopedContractId === "guest-book.testnet" ? "addMessage" : "pay_counterparty");

    const artifact = await this.signScopedTransaction(existing.request, chosenMethod);
    const updated = this.store.resolveApproval(
      approvalId,
      "approved",
      reviewer,
      note ?? "Reviewed WARN signals and authorized scoped execution.",
      artifact,
    )!;

    this.store.recordSpend({
      network: existing.request.network,
      agentId: existing.request.agentId,
      receiverId: existing.request.receiverId,
      amountNear: existing.request.amountNear,
      txHash: artifact.txHash,
    });

    const auditEntry = this.store.appendAuditLog({
      action: "human_approved",
      network: existing.request.network,
      agentId: existing.request.agentId,
      receiverId: existing.request.receiverId,
      amountNear: existing.request.amountNear,
      verdict: existing.evaluation.verdict,
      riskScore: existing.evaluation.riskScore,
      reasons: [`Approved by ${reviewer}: ${note ?? "Authorized WARN payment"}`],
      txHash: artifact.txHash,
      approvalId,
    });

    return { approval: updated, artifact, auditEntry };
  }

  rejectPending(
    approvalId: string,
    reviewer = "operator-human",
    note?: string,
  ): { approval: ApprovalRequest; auditEntry: AuditLogEntry } {
    const existing = this.store.getApproval(approvalId);
    if (!existing) {
      throw new Error(`Approval request "${approvalId}" not found.`);
    }
    if (existing.status !== "pending") {
      throw new Error(`Approval request "${approvalId}" is already ${existing.status}.`);
    }

    const updated = this.store.resolveApproval(
      approvalId,
      "rejected",
      reviewer,
      note ?? "Rejected after reviewing WARN signals.",
    )!;

    const auditEntry = this.store.appendAuditLog({
      action: "human_rejected",
      network: existing.request.network,
      agentId: existing.request.agentId,
      receiverId: existing.request.receiverId,
      amountNear: existing.request.amountNear,
      verdict: existing.evaluation.verdict,
      riskScore: existing.evaluation.riskScore,
      reasons: [`Rejected by ${reviewer}: ${note ?? "Operator denied payment"}`],
      approvalId,
    });

    return { approval: updated, auditEntry };
  }
}
