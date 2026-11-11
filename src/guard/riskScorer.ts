import { v4 as uuidv4 } from "uuid";
import type { NearDataFetcher } from "./nearClient.js";
import type { NearGuardStore } from "./store.js";
import { analyzePromptInjection } from "./injectionDetector.js";
import type {
  CounterpartyEvaluationResponse,
  EvaluateRequest,
  RiskSignal,
  Verdict,
} from "./types.js";

const SUSPICIOUS_NAME_REGEX =
  /(airdrop|claim[-_]?bonus|free[-_]?near|support[-_]?desk|urgent[-_]?verify|drain|wallet[-_]?sync|seed[-_]?verify|official[-_]?claim)/i;

const KNOWN_BRAND_LOOKALIKE_TARGETS = ["intents.near", "ref.finance", "wrap.near", "sweat_welcome.near"];

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[m][n];
}

export class CounterpartyRiskService {
  private readonly store: NearGuardStore;
  private readonly nearFetcher: NearDataFetcher;

  constructor(store: NearGuardStore, nearFetcher: NearDataFetcher) {
    this.store = store;
    this.nearFetcher = nearFetcher;
  }

  async evaluate(request: EvaluateRequest): Promise<CounterpartyEvaluationResponse> {
    const network = request.network;
    const receiverId = request.receiverId.toLowerCase().trim();
    const agentId = request.agentId.toLowerCase().trim();
    const policy = this.store.getPolicy();

    const [onChain, injection] = await Promise.all([
      this.nearFetcher.fetchCounterpartySnapshot(receiverId, agentId, network),
      analyzePromptInjection({
        instruction: request.instruction,
        memo: request.memo,
        receiverId,
      }),
    ]);

    const signals: RiskSignal[] = [];
    let hardBlocked = false;
    let rawScore = 0;

    const addSignal = (signal: RiskSignal) => {
      signals.push(signal);
      rawScore += signal.scoreImpact;
    };

    // Signal 1: Shared Evidence-Backed Agent Blocklist
    const blockEntry = this.store.findBlocklistEntry(receiverId, network);
    if (blockEntry) {
      hardBlocked = true;
      addSignal({
        id: "shared_blocklist_hit",
        name: "Shared Agent Threat Blocklist",
        category: "blocklist",
        status: "danger",
        scoreImpact: 90,
        summary: `BLOCKED on shared agent blocklist (${blockEntry.category}) reported by ${blockEntry.reportedBy}: "${blockEntry.reason}"`,
        source: "near-guard/shared-blocklist",
        details: {
          entryId: blockEntry.id,
          category: blockEntry.category,
          evidence: blockEntry.evidence,
        },
      });
    } else {
      addSignal({
        id: "shared_blocklist_clear",
        name: "Shared Agent Threat Blocklist",
        category: "blocklist",
        status: "pass",
        scoreImpact: 0,
        summary: "No matching threat reports in the evidence-backed blocklist.",
        source: "near-guard/shared-blocklist",
      });
    }

    // Signal 2: Account Format & On-Chain Existence
    if (!onChain.validAccountIdFormat) {
      hardBlocked = true;
      addSignal({
        id: "invalid_account_format",
        name: "NEAR Account Identity",
        category: "identity",
        status: "danger",
        scoreImpact: 85,
        summary: `Invalid NEAR account ID syntax "${receiverId}".`,
        source: "near-kit/isValidAccountId",
      });
    } else if (!onChain.rpcAvailable) {
      addSignal({
        id: "rpc_unavailable",
        name: "NEAR RPC Account Check",
        category: "identity",
        status: "unavailable",
        scoreImpact: 25,
        summary: `Live NEAR RPC could not verify account (${onChain.rpcError ?? "unreachable"}); elevated caution applied.`,
        source: onChain.rpcEndpoint,
      });
    } else if (onChain.exists === false) {
      if (!policy.allowUnregisteredReceivers) {
        hardBlocked = true;
        addSignal({
          id: "account_does_not_exist",
          name: "NEAR On-Chain Existence",
          category: "identity",
          status: "danger",
          scoreImpact: 75,
          summary: `Account "${receiverId}" does not exist on NEAR ${network} (unregistered / typo risk).`,
          source: onChain.rpcEndpoint,
        });
      } else {
        addSignal({
          id: "account_unregistered_warn",
          name: "NEAR On-Chain Existence",
          category: "identity",
          status: "caution",
          scoreImpact: 35,
          summary: `Account "${receiverId}" is not registered on NEAR ${network}.`,
          source: onChain.rpcEndpoint,
        });
      }
    } else {
      addSignal({
        id: "account_exists",
        name: "NEAR On-Chain Existence",
        category: "identity",
        status: "pass",
        scoreImpact: 0,
        summary: `Verified active account on NEAR ${network} (balance: ${onChain.balanceNear ?? "?"} NEAR, storage: ${onChain.storageBytes ?? 0} bytes).`,
        source: onChain.rpcEndpoint,
      });
    }

    // Signal 3: Prompt Injection & Redirect Guard
    if (injection.detected) {
      if (injection.severity === "critical") hardBlocked = true;
      addSignal({
        id: "prompt_injection_detected",
        name: "Instruction & Memo Security Scan",
        category: "prompt_security",
        status: injection.severity === "critical" ? "danger" : "caution",
        scoreImpact: injection.scoreImpact,
        summary:
          injection.matchedRules.length > 0
            ? `Adversarial pattern(s) detected: ${injection.matchedRules.map((r) => `${r.label} ("${r.excerpt}")`).join("; ")}.`
            : injection.aiAnalysis?.explanation ?? "Suspicious instruction semantics flagged.",
        source: injection.aiAnalysis?.used
          ? "near-guard/regex + near-ai-cloud-tee"
          : "near-guard/prompt-scanner",
        details: {
          matchedRules: injection.matchedRules,
          mentionedOtherAccounts: injection.mentionedOtherAccounts,
          aiAnalysis: injection.aiAnalysis,
        },
      });
    } else if (request.instruction || request.memo) {
      addSignal({
        id: "prompt_injection_clean",
        name: "Instruction & Memo Security Scan",
        category: "prompt_security",
        status: "pass",
        scoreImpact: 0,
        summary: "No prompt-injection, coercion, or destination-spoofing signatures detected.",
        source: injection.aiAnalysis?.used
          ? "near-guard/regex + near-ai-cloud-tee"
          : "near-guard/prompt-scanner",
      });
    }

    // Signal 4: Phishing Naming & Typosquatting Check
    const lookalikeMatch = KNOWN_BRAND_LOOKALIKE_TARGETS.find((brand) => {
      if (receiverId === brand) return false;
      return levenshtein(receiverId, brand) <= 2;
    });

    if (SUSPICIOUS_NAME_REGEX.test(receiverId) || lookalikeMatch) {
      addSignal({
        id: "phishing_name_heuristic",
        name: "Phishing & Lookalike Heuristic",
        category: "identity",
        status: "danger",
        scoreImpact: 45,
        summary: lookalikeMatch
          ? `Account name closely resembles high-value protocol "${lookalikeMatch}" (possible typosquatting).`
          : `Account ID "${receiverId}" matches known phishing/airdrop-lure naming pattern.`,
        source: "near-guard/name-heuristics",
      });
    }

    // Signal 5: Spending Limits, Method Blocklist & Receiver Allowlist
    const dailySpentBefore = this.store.getDailySpentNear(agentId, network);
    const projectedDailyTotal = Number((dailySpentBefore + request.amountNear).toFixed(6));

    if (request.amountNear > policy.maxPerTxNear) {
      hardBlocked = true;
      addSignal({
        id: "per_tx_limit_exceeded",
        name: "Per-Transaction Spend Cap",
        category: "policy_budget",
        status: "danger",
        scoreImpact: 75,
        summary: `Requested ${request.amountNear} NEAR exceeds max per-tx limit (${policy.maxPerTxNear} NEAR).`,
        source: "near-guard/policy-engine",
      });
    } else if (projectedDailyTotal > policy.dailySpendCapNear) {
      hardBlocked = true;
      addSignal({
        id: "daily_cap_exceeded",
        name: "Rolling 24h Spend Budget",
        category: "policy_budget",
        status: "danger",
        scoreImpact: 75,
        summary: `Projected 24h total (${projectedDailyTotal} NEAR) exceeds daily budget cap (${policy.dailySpendCapNear} NEAR).`,
        source: "near-guard/policy-engine",
      });
    } else {
      addSignal({
        id: "budget_within_limits",
        name: "Per-Tx & 24h Spending Budget",
        category: "policy_budget",
        status: "pass",
        scoreImpact: 0,
        summary: `Amount ${request.amountNear} NEAR fits policy caps (24h spend after tx: ${projectedDailyTotal}/${policy.dailySpendCapNear} NEAR).`,
        source: "near-guard/policy-engine",
      });
    }

    if (request.methodName && policy.blockedMethods.includes(request.methodName.trim())) {
      hardBlocked = true;
      addSignal({
        id: "blocked_method",
        name: "Contract Method Restrictions",
        category: "policy_budget",
        status: "danger",
        scoreImpact: 80,
        summary: `Method "${request.methodName}" is explicitly forbidden by agent security policy.`,
        source: "near-guard/policy-engine",
      });
    }

    const isAllowlisted = policy.allowlistedReceivers.some(
      (a) => a.toLowerCase() === receiverId,
    );
    if (isAllowlisted && !blockEntry) {
      addSignal({
        id: "allowlisted_counterparty",
        name: "Verified Allowlist Match",
        category: "policy_budget",
        status: "pass",
        scoreImpact: -20,
        summary: `Receiver "${receiverId}" is on the operator's verified allowlist.`,
        source: "near-guard/policy-engine",
      });
    }

    // Signal 6: Contract Inspection, Recent Code Deployment & Snapshot Mutation
    if (onChain.exists === true) {
      if (onChain.hasContract) {
        const recentUpgradeHours = onChain.hoursSinceLastCodeDeploy;
        const isRecentUpgrade =
          recentUpgradeHours !== null &&
          recentUpgradeHours <= policy.warnOnContractCodeChangeHours;

        if (onChain.codeHashChangedFromSnapshot) {
          addSignal({
            id: "contract_code_hash_mutated",
            name: "Smart Contract Code Integrity",
            category: "contract_code",
            status: "danger",
            scoreImpact: 45,
            summary: `ALERT: Contract WASM code_hash changed from previously observed ${onChain.previousSnapshotCodeHash?.slice(0, 12)}... to ${onChain.codeHash?.slice(0, 12)}...`,
            source: "near-guard/code-hash-monitor",
            details: {
              previousCodeHash: onChain.previousSnapshotCodeHash,
              currentCodeHash: onChain.codeHash,
            },
          });
        } else if (isRecentUpgrade) {
          addSignal({
            id: "contract_recent_deploy",
            name: "Smart Contract Code Recency",
            category: "contract_code",
            status: "caution",
            scoreImpact: 30,
            summary: `Smart contract deployed or upgraded ${recentUpgradeHours}h ago (inside ${policy.warnOnContractCodeChangeHours}h cooldown window; tx ${onChain.recentDeployContractTx?.slice(0, 12)}...).`,
            source: "nearblocks-v3/txns",
          });
        } else {
          addSignal({
            id: "contract_code_stable",
            name: "Smart Contract Code Integrity",
            category: "contract_code",
            status: "pass",
            scoreImpact: 0,
            summary: `Receiver holds smart contract code (${onChain.codeHash?.slice(0, 12)}...) with no recent upgrade detected.`,
            source: onChain.rpcEndpoint,
          });
        }

        // Key Lock Posture on Contract
        if (onChain.locked === true || onChain.fullAccessKeyCount === 0) {
          addSignal({
            id: "contract_locked_immutable",
            name: "Counterparty Key Lock Posture",
            category: "key_posture",
            status: "pass",
            scoreImpact: -5,
            summary: "Counterparty contract has 0 FullAccess keys (immutable; deployer cannot silently swap code).",
            source: `${onChain.rpcEndpoint} (view_access_key_list)`,
          });
        } else if ((onChain.fullAccessKeyCount ?? 0) > 0) {
          addSignal({
            id: "contract_mutable_full_access",
            name: "Counterparty Key Lock Posture",
            category: "key_posture",
            status: "caution",
            scoreImpact: isAllowlisted ? 5 : 20,
            summary: `Contract holds ${onChain.fullAccessKeyCount} FullAccess key(s); maintainer can redeploy WASM at any time.`,
            source: `${onChain.rpcEndpoint} (view_access_key_list)`,
          });
        }
      } else {
        addSignal({
          id: "eoa_no_contract",
          name: "Account Code Posture",
          category: "contract_code",
          status: "pass",
          scoreImpact: 0,
          summary: "Standard account (no deployed WASM contract code).",
          source: onChain.rpcEndpoint,
        });
      }
    }

    // Signal 7: Account Age & Transaction Activity History (NearBlocks v3)
    if (!onChain.indexerAvailable) {
      addSignal({
        id: "indexer_unavailable",
        name: "Account Age & Activity History",
        category: "age_activity",
        status: "unavailable",
        scoreImpact: isAllowlisted ? 0 : 15,
        summary: `NearBlocks v3 history unavailable (${onChain.indexerError ?? "timeout"}); age & failure rate could not be confirmed.`,
        source: "nearblocks-v3",
      });
    } else if (onChain.exists === true) {
      if (onChain.accountAgeDays !== null && onChain.accountAgeDays < policy.minAccountAgeDays) {
        addSignal({
          id: "account_too_new",
          name: "Account Age Threshold",
          category: "age_activity",
          status: "caution",
          scoreImpact: 25,
          summary: `Young account created ${onChain.accountAgeDays} days ago (policy minimum: ${policy.minAccountAgeDays} days).`,
          source: "nearblocks-v3/accounts",
        });
      } else if (onChain.accountAgeDays !== null) {
        addSignal({
          id: "account_age_mature",
          name: "Account Age Threshold",
          category: "age_activity",
          status: "pass",
          scoreImpact: -5,
          summary: `Mature account created ${onChain.accountAgeDays} days ago (${onChain.createdAtIso?.slice(0, 10)}).`,
          source: "nearblocks-v3/accounts",
        });
      }

      if (onChain.recentTxCount !== null && onChain.recentTxCount === 0) {
        addSignal({
          id: "zero_recent_activity",
          name: "Recent Transaction Activity",
          category: "age_activity",
          status: "caution",
          scoreImpact: 20,
          summary: "Zero recent on-chain transactions found for receiver.",
          source: "nearblocks-v3/txns",
        });
      } else if (
        onChain.recentSuccessRate !== null &&
        onChain.recentSuccessRate < 0.7 &&
        (onChain.recentTxCount ?? 0) >= 3
      ) {
        addSignal({
          id: "high_tx_failure_rate",
          name: "Transaction Success Reliability",
          category: "age_activity",
          status: "caution",
          scoreImpact: 25,
          summary: `Elevated recent transaction failure rate (${Math.round((1 - onChain.recentSuccessRate) * 100)}% failed out of ${onChain.recentTxCount} txns).`,
          source: "nearblocks-v3/txns",
        });
      } else if (onChain.recentTxCount !== null && onChain.recentSuccessRate !== null) {
        addSignal({
          id: "healthy_activity",
          name: "Recent Transaction Activity",
          category: "age_activity",
          status: "pass",
          scoreImpact: -5,
          summary: `${onChain.recentTxCount} recent txns sampled with ${Math.round(onChain.recentSuccessRate * 100)}% execution success.`,
          source: "nearblocks-v3/txns",
        });
      }
    }

    // Signal 8: Prior Agent <-> Counterparty Interaction History
    const priorCount = onChain.priorInteractionsWithAgent ?? 0;
    if (priorCount > 0) {
      addSignal({
        id: "prior_interaction_verified",
        name: "Prior Agent-Counterparty History",
        category: "prior_history",
        status: "pass",
        scoreImpact: -10,
        summary: `Agent "${agentId}" has ${priorCount} prior verified interaction(s) with "${receiverId}".`,
        source: onChain.priorInteractionSampleTx
          ? `nearblocks/receipt (${onChain.priorInteractionSampleTx.slice(0, 12)}...)`
          : "near-guard/spend-ledger",
      });
    } else if (!isAllowlisted) {
      addSignal({
        id: "first_time_counterparty",
        name: "Prior Agent-Counterparty History",
        category: "prior_history",
        status: policy.requirePriorInteraction ? "danger" : "caution",
        scoreImpact: policy.requirePriorInteraction ? 35 : 20,
        summary: policy.requirePriorInteraction
          ? `No prior verified interactions between "${agentId}" and "${receiverId}" (policy requires prior history or allowlist).`
          : `First-time counterparty for "${agentId}" with zero prior shared transactions.`,
        source: "nearblocks-v3 + near-guard/spend-ledger",
      });
    }

    const riskScore = Math.max(0, Math.min(100, rawScore));

    let verdict: Verdict = "ALLOW";
    if (hardBlocked || riskScore >= policy.blockScoreThreshold) {
      verdict = "BLOCK";
    } else if (riskScore >= policy.warnScoreThreshold || onChain.codeHashChangedFromSnapshot) {
      verdict = "WARN";
    }

    // Collect concise top reasons (prioritizing danger/caution/unavailable items, else passing highlights)
    const concerningReasons = signals
      .filter((s) => s.status === "danger" || s.status === "caution" || s.status === "unavailable")
      .map((s) => s.summary);

    const reasons =
      concerningReasons.length > 0
        ? concerningReasons
        : signals
            .filter((s) => s.status === "pass")
            .slice(0, 4)
            .map((s) => s.summary);

    const evaluation: CounterpartyEvaluationResponse = {
      evaluationId: `eval-${uuidv4().slice(0, 8)}`,
      verdict,
      riskScore,
      hardBlocked,
      reasons,
      signals,
      onChain,
      injection,
      policySummary: {
        maxPerTxNear: policy.maxPerTxNear,
        dailySpendCapNear: policy.dailySpendCapNear,
        dailySpentBeforeNear: dailySpentBefore,
        dailyRemainingNear: Number(
          Math.max(0, policy.dailySpendCapNear - dailySpentBefore).toFixed(6),
        ),
      },
      evaluatedAt: new Date().toISOString(),
    };

    this.store.appendAuditLog({
      action: "evaluate",
      network,
      agentId,
      receiverId,
      amountNear: request.amountNear,
      verdict,
      riskScore,
      reasons,
    });

    return evaluation;
  }
}
