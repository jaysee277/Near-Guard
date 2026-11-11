import { AccountDoesNotExistError, Near, isValidAccountId } from "near-kit";
import type { NearOnChainSnapshot, NetworkId } from "./types.js";
import type { NearGuardStore } from "./store.js";

const RPC_ENDPOINTS: Record<NetworkId, string> = {
  mainnet: "https://free.rpc.fastnear.com",
  testnet: "https://test.rpc.fastnear.com",
};

const NEARBLOCKS_V3_BASES: Record<NetworkId, string> = {
  mainnet: "https://api.nearblocks.io/v3",
  testnet: "https://api-testnet.nearblocks.io/v3",
};

const FASTNEAR_BASES: Record<NetworkId, string> = {
  mainnet: "https://api.fastnear.com/v1",
  testnet: "https://test.api.fastnear.com/v1",
};

interface NearBlocksAccountResp {
  data?: {
    account_id?: string;
    created?: {
      block_timestamp?: string;
      transaction_hash?: string;
    };
    locked?: boolean;
  };
}

interface NearBlocksTxnItem {
  transaction_hash: string;
  signer_account_id: string;
  receiver_account_id: string;
  block_timestamp?: string;
  outcomes?: { status?: boolean };
  actions?: Array<{ action?: string; method?: string | null }>;
}

interface NearBlocksTxnsResp {
  data?: NearBlocksTxnItem[];
}

interface FastNearFullResp {
  account_id?: string;
  tokens?: unknown[];
}

export interface NearDataFetcher {
  fetchCounterpartySnapshot(
    accountId: string,
    agentId: string,
    network: NetworkId,
  ): Promise<NearOnChainSnapshot>;
  fetchFinalBlockHash(network: NetworkId): Promise<{ blockHash: string; live: boolean }>;
  checkAccessKeyPermission(
    network: NetworkId,
    accountId: string,
    publicKey: string,
  ): Promise<
    | { found: true; permission: "FullAccess" | "FunctionCall" | "GasKeyFullAccess" | "GasKeyFunctionCall"; details?: Record<string, unknown> }
    | { found: false; reason: string }
  >;
}

async function fetchJsonWithTimeout<T>(url: string, timeoutMs = 4500): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: "application/json" },
    });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status} from ${new URL(url).hostname}`);
    }
    return (await res.json()) as T;
  } finally {
    clearTimeout(timer);
  }
}

function nsTimestampToDate(nsStr?: string | null): Date | null {
  if (!nsStr) return null;
  const ns = Number(nsStr);
  if (!Number.isFinite(ns) || ns <= 0) return null;
  return new Date(Math.floor(ns / 1_000_000));
}

export class LiveNearDataFetcher implements NearDataFetcher {
  private clients: Record<NetworkId, Near>;
  private readonly store?: NearGuardStore;

  constructor(store?: NearGuardStore) {
    this.store = store;
    this.clients = {
      mainnet: new Near({ network: "mainnet", rpcUrl: RPC_ENDPOINTS.mainnet }),
      testnet: new Near({ network: "testnet", rpcUrl: RPC_ENDPOINTS.testnet }),
    };
  }

  getClient(network: NetworkId): Near {
    return this.clients[network];
  }

  async fetchFinalBlockHash(network: NetworkId): Promise<{ blockHash: string; live: boolean }> {
    try {
      const block = await this.clients[network].rpc.getBlock({ finality: "final" });
      return { blockHash: block.header.hash, live: true };
    } catch {
      // Deterministic 32-byte base58 genesis-style fallback hash if airgapped
      return { blockHash: "11111111111111111111111111111111", live: false };
    }
  }

  async checkAccessKeyPermission(
    network: NetworkId,
    accountId: string,
    publicKey: string,
  ): Promise<
    | {
        found: true;
        permission: "FullAccess" | "FunctionCall" | "GasKeyFullAccess" | "GasKeyFunctionCall";
        details?: Record<string, unknown>;
      }
    | { found: false; reason: string }
  > {
    try {
      const view = await this.clients[network].getAccessKey(accountId, publicKey);
      if (!view) {
        return { found: false, reason: "Access key not registered on-chain for this account." };
      }
      if (view.permission === "FullAccess") {
        return { found: true, permission: "FullAccess" };
      }
      if ("FunctionCall" in view.permission) {
        return {
          found: true,
          permission: "FunctionCall",
          details: view.permission.FunctionCall,
        };
      }
      if ("GasKeyFullAccess" in view.permission) {
        return { found: true, permission: "GasKeyFullAccess" };
      }
      return {
        found: true,
        permission: "GasKeyFunctionCall",
        details: view.permission.GasKeyFunctionCall,
      };
    } catch (err) {
      return {
        found: false,
        reason: err instanceof Error ? err.message : "Failed to query access key via RPC",
      };
    }
  }

  async fetchCounterpartySnapshot(
    rawAccountId: string,
    rawAgentId: string,
    network: NetworkId,
  ): Promise<NearOnChainSnapshot> {
    const accountId = rawAccountId.toLowerCase().trim();
    const agentId = rawAgentId.toLowerCase().trim();
    const validFormat = isValidAccountId(accountId);
    const rpcEndpoint = RPC_ENDPOINTS[network];

    const snapshot: NearOnChainSnapshot = {
      network,
      accountId,
      validAccountIdFormat: validFormat,
      exists: null,
      rpcAvailable: false,
      rpcEndpoint,
      balanceNear: null,
      availableNear: null,
      stakedNear: null,
      storageBytes: null,
      hasContract: null,
      codeHash: null,
      fullAccessKeyCount: null,
      functionCallKeyCount: null,
      locked: null,
      indexerAvailable: false,
      createdAtIso: null,
      createdTxHash: null,
      accountAgeDays: null,
      recentTxCount: null,
      recentSuccessRate: null,
      recentDeployContractAt: null,
      recentDeployContractTx: null,
      hoursSinceLastCodeDeploy: null,
      priorInteractionsWithAgent: null,
      priorInteractionSampleTx: null,
      fastNearAvailable: false,
      fastNearTokenCount: null,
      codeHashChangedFromSnapshot: false,
      previousSnapshotCodeHash: null,
    };

    if (!validFormat) {
      snapshot.exists = false;
      snapshot.rpcError = "Account ID fails NEAR protocol naming syntax validation.";
      return snapshot;
    }

    const near = this.clients[network];

    // 1. Live NEAR RPC: view_account + view_access_key_list
    try {
      const accountState = await near.getAccount(accountId);
      snapshot.rpcAvailable = true;
      snapshot.exists = true;
      snapshot.balanceNear = accountState.balance;
      snapshot.availableNear = accountState.available;
      snapshot.stakedNear = accountState.staked;
      snapshot.storageBytes = accountState.storageBytes;
      snapshot.hasContract = accountState.hasContract;
      snapshot.codeHash = accountState.codeHash;

      if (this.store && accountState.hasContract) {
        const diff = this.store.recordCodeHash(accountId, network, accountState.codeHash);
        snapshot.codeHashChangedFromSnapshot = diff.changed;
        snapshot.previousSnapshotCodeHash = diff.previousCodeHash;
      }

      try {
        const keyList = await near.getAccessKeys(accountId);
        let fullCount = 0;
        let fcCount = 0;
        for (const k of keyList.keys) {
          if (k.access_key.permission === "FullAccess" || "GasKeyFullAccess" in (typeof k.access_key.permission === "object" ? k.access_key.permission : {})) {
            fullCount += 1;
          } else {
            fcCount += 1;
          }
        }
        snapshot.fullAccessKeyCount = fullCount;
        snapshot.functionCallKeyCount = fcCount;
        snapshot.locked = keyList.keys.length === 0 || fullCount === 0;
      } catch {
        // Non-fatal if key list sub-query fails
      }
    } catch (err) {
      if (
        err instanceof AccountDoesNotExistError ||
        (err instanceof Error && /does not exist|UNKNOWN_ACCOUNT/i.test(err.message))
      ) {
        snapshot.rpcAvailable = true;
        snapshot.exists = false;
      } else {
        snapshot.rpcAvailable = false;
        snapshot.exists = null;
        snapshot.rpcError = err instanceof Error ? err.message : "NEAR RPC request failed";
      }
    }

    // 2. Live NearBlocks v3 Indexer (Account creation age + recent transactions + deploy events)
    const nbBase = NEARBLOCKS_V3_BASES[network];
    try {
      const [acctRes, txRes] = await Promise.all([
        fetchJsonWithTimeout<NearBlocksAccountResp>(
          `${nbBase}/accounts/${encodeURIComponent(accountId)}`,
        ),
        fetchJsonWithTimeout<NearBlocksTxnsResp>(
          `${nbBase}/accounts/${encodeURIComponent(accountId)}/txns?limit=25`,
        ),
      ]);

      snapshot.indexerAvailable = true;
      const createdDate = nsTimestampToDate(acctRes.data?.created?.block_timestamp);
      if (createdDate) {
        snapshot.createdAtIso = createdDate.toISOString();
        snapshot.createdTxHash = acctRes.data?.created?.transaction_hash ?? null;
        snapshot.accountAgeDays = Number(
          ((Date.now() - createdDate.getTime()) / (1000 * 60 * 60 * 24)).toFixed(1),
        );
      }
      if (snapshot.locked === null && typeof acctRes.data?.locked === "boolean") {
        snapshot.locked = acctRes.data.locked;
      }

      const txns = Array.isArray(txRes.data) ? txRes.data : [];
      snapshot.recentTxCount = txns.length;

      if (txns.length > 0) {
        const succeeded = txns.filter((t) => t.outcomes?.status === true).length;
        snapshot.recentSuccessRate = Number((succeeded / txns.length).toFixed(3));

        for (const txn of txns) {
          const hasDeploy = txn.actions?.some(
            (a) =>
              a.action === "DEPLOY_CONTRACT" ||
              a.action === "DEPLOY_GLOBAL_CONTRACT",
          );
          if (hasDeploy && !snapshot.recentDeployContractTx) {
            const deployDate = nsTimestampToDate(txn.block_timestamp);
            snapshot.recentDeployContractTx = txn.transaction_hash;
            if (deployDate) {
              snapshot.recentDeployContractAt = deployDate.toISOString();
              snapshot.hoursSinceLastCodeDeploy = Number(
                ((Date.now() - deployDate.getTime()) / (1000 * 60 * 60)).toFixed(1),
              );
            }
          }
        }

        const priorWithAgent = txns.filter(
          (t) =>
            t.signer_account_id?.toLowerCase() === agentId ||
            t.receiver_account_id?.toLowerCase() === agentId,
        );
        snapshot.priorInteractionsWithAgent = priorWithAgent.length;
        snapshot.priorInteractionSampleTx =
          priorWithAgent[0]?.transaction_hash ?? null;
      } else {
        snapshot.priorInteractionsWithAgent = 0;
      }

      // Also check local verified receipts for prior agent <-> counterparty txs
      if (this.store) {
        const localPrior = this.store.getLocalPriorInteractionsCount(
          agentId,
          accountId,
          network,
        );
        if (localPrior.count > 0) {
          snapshot.priorInteractionsWithAgent =
            (snapshot.priorInteractionsWithAgent ?? 0) + localPrior.count;
          snapshot.priorInteractionSampleTx ??= localPrior.lastTxHash;
        }
      }
    } catch (err) {
      snapshot.indexerAvailable = false;
      snapshot.indexerError =
        err instanceof Error ? err.message : "NearBlocks v3 indexer unavailable";
      // Still surface local verified interaction history if available
      if (this.store) {
        const localPrior = this.store.getLocalPriorInteractionsCount(
          agentId,
          accountId,
          network,
        );
        snapshot.priorInteractionsWithAgent = localPrior.count;
        snapshot.priorInteractionSampleTx = localPrior.lastTxHash;
      }
    }

    // 3. FastNEAR REST API cross-check (FT / account assets telemetry)
    if (snapshot.exists !== false) {
      const fnBase = FASTNEAR_BASES[network];
      try {
        const fnData = await fetchJsonWithTimeout<FastNearFullResp>(
          `${fnBase}/account/${encodeURIComponent(accountId)}/full`,
          3500,
        );
        snapshot.fastNearAvailable = true;
        snapshot.fastNearTokenCount = Array.isArray(fnData.tokens)
          ? fnData.tokens.length
          : 0;
      } catch {
        snapshot.fastNearAvailable = false;
      }
    }

    return snapshot;
  }
}
