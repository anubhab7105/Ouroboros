import type {
  AccountIngestRecord,
  ComplaintIngestRecord,
  EntityIngestRecord,
  EntityLinkIngestRecord,
  TransactionIngestRecord,
} from '@/types/ingestion';

/**
 * A synthetic dataset generator, in the browser.
 *
 * There is no "generate data" endpoint — the API ingests records and nothing
 * more — so rather than pretend otherwise, this builds a coherent dataset
 * client-side and loads it through the ordinary ingestion endpoints. The data
 * that results is exactly as traceable as any other import: it carries a
 * source system and a batch id, and it can be loaded as a dry run first.
 *
 * The point of generating rather than randomising is that the typologies have
 * to be *there* to be found. A pile of uniformly random transfers produces no
 * fan-in, no pass-through and no layering chain, so every rule returns nothing
 * and the platform looks broken when it is working perfectly. This generator
 * plants each shape deliberately and in known places:
 *
 * - **Collection (fan-in):** many small senders into one account.
 * - **Pass-through:** funds in and almost all of them out within hours.
 * - **Distribution (fan-out):** one account paying many others.
 * - **Layering chain:** a path of several hops passing on nearly what it got.
 * - **Dormant reactivation:** an old account with a long gap, then a burst.
 * - **Shared identifiers:** a device and a UPI handle shared across a cluster.
 * - **Ordinary accounts:** the majority, with unremarkable activity, because a
 *   dataset of nothing but fraud teaches an analyst nothing about precision.
 *
 * Everything is derived from a seed, so a generated dataset can be reproduced
 * exactly — which matters when someone reports that a rule fired oddly.
 */

export interface GenerateOptions {
  /** Ordinary accounts with unremarkable activity. */
  normalAccounts: number;
  /** How many of each suspicious pattern to plant. */
  patterns: number;
  /** Days of history to spread activity over. */
  days: number;
  /** Complaints to raise against the planted patterns. */
  complaints: number;
  seed: number;
  currency: string;
}

export const DEFAULT_GENERATE_OPTIONS: GenerateOptions = {
  normalAccounts: 40,
  patterns: 3,
  days: 60,
  complaints: 12,
  seed: 20260101,
  currency: 'INR',
};

export interface GeneratedDataset {
  accounts: AccountIngestRecord[];
  transactions: TransactionIngestRecord[];
  complaints: ComplaintIngestRecord[];
  entities: EntityIngestRecord[];
  entityLinks: EntityLinkIngestRecord[];
  /** What was planted, so the loader can tell the user what to look for. */
  plantedPatterns: Array<{ kind: string; accountIds: string[]; note: string }>;
}

/** A small deterministic PRNG. Reproducible datasets need one. */
function makeRandom(seed: number) {
  let state = seed >>> 0 || 1;

  return () => {
    // xorshift32: short, fast, and good enough for synthetic data.
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    return state / 0xffffffff;
  };
}

const CHANNELS = ['UPI', 'IMPS', 'NEFT', 'RTGS', 'CARD'] as const;
const ACCOUNT_TYPES = ['INDIVIDUAL', 'BUSINESS', 'MERCHANT'] as const;

const COMPLAINT_CATEGORIES = [
  'upi_fraud',
  'phishing',
  'investment_scam',
  'job_scam',
  'loan_app_harassment',
  'card_not_present',
] as const;

export function generateDataset(options: GenerateOptions): GeneratedDataset {
  const random = makeRandom(options.seed);
  const now = Date.now();
  const dayMs = 24 * 60 * 60 * 1000;

  const accounts: AccountIngestRecord[] = [];
  const transactions: TransactionIngestRecord[] = [];
  const complaints: ComplaintIngestRecord[] = [];
  const entities: EntityIngestRecord[] = [];
  const entityLinks: EntityLinkIngestRecord[] = [];
  const plantedPatterns: GeneratedDataset['plantedPatterns'] = [];

  const pad = (value: number, width = 4) => String(value).padStart(width, '0');
  const iso = (offsetMs: number) => new Date(now - offsetMs).toISOString();

  let accountSeq = 0;
  let txnSeq = 0;

  /** Create an account opened `ageDays` ago. */
  const addAccount = (ageDays: number, type?: string, status = 'ACTIVE'): string => {
    const id = `acc_${options.seed}_${pad(++accountSeq)}`;

    accounts.push({
      id,
      account_type:
        type ?? ACCOUNT_TYPES[Math.floor(random() * ACCOUNT_TYPES.length)] ?? 'INDIVIDUAL',
      status,
      created_at: iso(ageDays * dayMs),
      metadata_json: { generated: true, seed: options.seed },
    });

    return id;
  };

  const addTransaction = (
    from: string,
    to: string,
    amount: number,
    offsetMs: number,
    status = 'COMPLETED',
    channel?: string,
  ) => {
    const reference = `TXN${options.seed}${pad(++txnSeq, 6)}`;

    transactions.push({
      reference,
      sender_account_id: from,
      receiver_account_id: to,
      // Two decimal places: the API takes a decimal and rounding here keeps
      // the ingested figures identical to what was generated.
      amount: Math.round(amount * 100) / 100,
      currency: options.currency,
      occurred_at: iso(offsetMs),
      status,
      channel: channel ?? CHANNELS[Math.floor(random() * CHANNELS.length)] ?? 'UPI',
      metadata_json: { generated: true },
    });

    return reference;
  };

  // ---------------------------------------------------------------- ordinary
  const ordinary: string[] = [];
  for (let index = 0; index < options.normalAccounts; index += 1) {
    ordinary.push(addAccount(120 + Math.floor(random() * 900)));
  }

  // Unremarkable activity: a handful of transfers each, modest amounts, and a
  // realistic minority that did not complete.
  for (const accountId of ordinary) {
    const count = 3 + Math.floor(random() * 8);

    for (let index = 0; index < count; index += 1) {
      const other = ordinary[Math.floor(random() * ordinary.length)]!;
      if (other === accountId) continue;

      const outbound = random() > 0.5;
      const amount = 200 + random() * 9_000;
      const offset = random() * options.days * dayMs;
      const status = random() > 0.94 ? (random() > 0.5 ? 'FAILED' : 'PENDING') : 'COMPLETED';

      addTransaction(
        outbound ? accountId : other,
        outbound ? other : accountId,
        amount,
        offset,
        status,
      );
    }
  }

  const victimPool: string[] = [];
  const suspectRefs: Array<{ reference: string; accountId: string }> = [];

  for (let pattern = 0; pattern < options.patterns; pattern += 1) {
    // ------------------------------------------------- collection (fan-in)
    {
      const collector = addAccount(10 + Math.floor(random() * 20));
      const senders: string[] = [];

      for (let index = 0; index < 14 + Math.floor(random() * 10); index += 1) {
        const sender = addAccount(200 + Math.floor(random() * 600));
        senders.push(sender);
        victimPool.push(sender);

        // Small, similar amounts arriving inside a couple of days: a shape no
        // ordinary account produces.
        const amount = 4_500 + random() * 1_200;
        const reference = addTransaction(
          sender,
          collector,
          amount,
          random() * 2 * dayMs,
          'COMPLETED',
          'UPI',
        );

        suspectRefs.push({ reference, accountId: collector });
      }

      plantedPatterns.push({
        kind: 'Collection account (fan-in)',
        accountIds: [collector],
        note: `${senders.length} senders paying similar amounts into one account within two days.`,
      });

      // --------------------------------------------------- pass-through
      const spender = addAccount(400 + Math.floor(random() * 300));
      const received = transactions
        .filter((txn) => txn.receiver_account_id === collector)
        .reduce((sum, txn) => sum + txn.amount, 0);

      // Nearly everything out again within hours, in two tranches.
      addTransaction(collector, spender, received * 0.62, 6 * 60 * 60 * 1000, 'COMPLETED', 'IMPS');
      addTransaction(collector, spender, received * 0.36, 3 * 60 * 60 * 1000, 'COMPLETED', 'IMPS');

      plantedPatterns.push({
        kind: 'Pass-through',
        accountIds: [collector, spender],
        note: 'Around 98% of what arrived left again within hours, which is the shape the rapid pass-through rule looks for.',
      });

      // ------------------------------------------- distribution (fan-out)
      const recipients: string[] = [];
      for (let index = 0; index < 11 + Math.floor(random() * 8); index += 1) {
        const recipient = addAccount(150 + Math.floor(random() * 500));
        recipients.push(recipient);
        addTransaction(spender, recipient, received * 0.05, random() * dayMs, 'COMPLETED');
      }

      plantedPatterns.push({
        kind: 'Distribution account (fan-out)',
        accountIds: [spender],
        note: `One account paying ${recipients.length} others in near-equal amounts.`,
      });
    }

    // ----------------------------------------------------- layering chain
    {
      const chain: string[] = [];
      for (let hop = 0; hop < 5; hop += 1) {
        chain.push(addAccount(30 + Math.floor(random() * 120)));
      }

      let amount = 180_000 + random() * 60_000;
      for (let hop = 0; hop < chain.length - 1; hop += 1) {
        // Each hop passes on 96-99%: high throughput across several hops.
        amount *= 0.96 + random() * 0.03;
        addTransaction(
          chain[hop]!,
          chain[hop + 1]!,
          amount,
          (chain.length - hop) * 8 * 60 * 60 * 1000,
          'COMPLETED',
          'NEFT',
        );
      }

      plantedPatterns.push({
        kind: 'Layering chain',
        accountIds: chain,
        note: 'Five hops, each passing on 96-99% of what it received. High throughput across a path is the layering shape — it does not prove the same funds travelled it.',
      });
    }

    // ------------------------------------------------ dormant reactivation
    {
      const dormant = addAccount(900 + Math.floor(random() * 400), undefined, 'DORMANT');
      const counterparty = ordinary[Math.floor(random() * ordinary.length)]!;

      // Old activity, a long silence, then a burst inside one day.
      addTransaction(dormant, counterparty, 1_500, 800 * dayMs);

      for (let index = 0; index < 9; index += 1) {
        addTransaction(
          counterparty,
          dormant,
          20_000 + random() * 15_000,
          random() * dayMs,
          'COMPLETED',
          'UPI',
        );
      }

      plantedPatterns.push({
        kind: 'Dormant reactivation',
        accountIds: [dormant],
        note: 'Quiet for over two years, then nine transfers in a single day.',
      });
    }

    // ------------------------------------------------- shared identifiers
    {
      const clusterSize = 4;
      const cluster: string[] = [];
      for (let index = 0; index < clusterSize; index += 1) {
        cluster.push(addAccount(20 + Math.floor(random() * 60)));
      }

      const deviceId = `ent_${options.seed}_dev_${pattern}`;
      const upiId = `ent_${options.seed}_upi_${pattern}`;

      entities.push({
        id: deviceId,
        entity_type: 'DEVICE',
        identifier_hash: `sha256:device:${options.seed}:${pattern}`,
        identifier_display: `device-${options.seed}-${pattern}`,
        source: 'synthetic-generator',
        first_seen_at: iso(60 * dayMs),
        last_seen_at: iso(dayMs),
      });

      entities.push({
        id: upiId,
        entity_type: 'UPI_ID',
        identifier_hash: `sha256:upi:${options.seed}:${pattern}`,
        identifier_display: `handle${pattern}@synthetic`,
        source: 'synthetic-generator',
        first_seen_at: iso(60 * dayMs),
        last_seen_at: iso(dayMs),
      });

      for (const accountId of cluster) {
        entityLinks.push({
          account_id: accountId,
          entity_id: deviceId,
          match_method: 'EXACT',
          verification_state: 'UNVERIFIED',
          valid_from: iso(60 * dayMs),
          source: 'synthetic-generator',
        });

        entityLinks.push({
          account_id: accountId,
          entity_id: upiId,
          match_method: 'EXACT',
          confidence: 0.9,
          verification_state: 'UNVERIFIED',
          valid_from: iso(60 * dayMs),
          source: 'synthetic-generator',
        });
      }

      plantedPatterns.push({
        kind: 'Shared identifier cluster',
        accountIds: cluster,
        note: `${clusterSize} accounts sharing one device and one UPI handle. Suggestive of common control; not proof of it.`,
      });
    }
  }

  // ---------------------------------------------------------- complaints
  for (let index = 0; index < options.complaints && index < suspectRefs.length; index += 1) {
    const target = suspectRefs[Math.floor(random() * suspectRefs.length)]!;
    const victim = victimPool[Math.floor(random() * victimPool.length)];
    const category =
      COMPLAINT_CATEGORIES[Math.floor(random() * COMPLAINT_CATEGORIES.length)] ?? 'upi_fraud';

    complaints.push({
      reference: `CMP${options.seed}${pad(index + 1, 5)}`,
      reported_at: iso(random() * options.days * dayMs),
      category,
      // The narrative names the transaction reference, which is what tier 1
      // correlation matches on, and the account, which is what the
      // complainant alleged rather than what the platform found.
      narrative_raw:
        `Synthetic complaint for testing. The complainant reports a transfer with reference ` +
        `${target.reference} that they did not authorise, and names account ` +
        `${target.accountId} as the recipient. This text is generated and describes no real ` +
        `person or event.`,
      transaction_reference: target.reference,
      victim_account_id: victim,
      suspected_account_id: target.accountId,
      amount: 4_500 + random() * 1_000,
      currency: options.currency,
      source: 'synthetic-generator',
      metadata_json: { generated: true, seed: options.seed },
    });
  }

  return { accounts, transactions, complaints, entities, entityLinks, plantedPatterns };
}

/** Row counts per entity type, for showing before a load. */
export function datasetSizes(dataset: GeneratedDataset): Record<string, number> {
  return {
    accounts: dataset.accounts.length,
    transactions: dataset.transactions.length,
    complaints: dataset.complaints.length,
    entities: dataset.entities.length,
    'entity-links': dataset.entityLinks.length,
  };
}
