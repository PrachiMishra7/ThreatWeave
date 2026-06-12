/**
 * threat-intel/db.ts
 * SQLite database layer using sql.js (a pure-JS/WASM SQLite port — no native compilation needed).
 *
 * Provides a singleton-style async initializer and CRUD helpers for threat indicators.
 * The DB file is persisted to `threatIntel.db` in the project root.
 *
 * WHY sql.js: The project runs on Node 22 on Windows. better-sqlite3 requires native
 * compilation via node-gyp which fails in SSL-restricted environments. sql.js is
 * a 100% JavaScript implementation with no native dependencies.
 */

import initSqlJs, { type Database, type SqlJsStatic } from "sql.js";
import fs from "fs";
import path from "path";
import type { ThreatIndicator } from "./schema.js";

// Resolve DB file path relative to project root
const DB_PATH = path.join(process.cwd(), "threatIntel.db");

/** Singleton database instance */
let _db: Database | null = null;
/** sql.js module reference (loaded once) */
let _SQL: SqlJsStatic | null = null;

/**
 * Initializes and returns the singleton SQLite database.
 * Creates the indicators table if it doesn't exist.
 * Loads existing data from disk if the DB file is present.
 */
export async function getDb(): Promise<Database> {
  if (_db) return _db;

  // Load sql.js WASM module
  _SQL = await initSqlJs();

  // Load existing DB file from disk, or create a new empty DB
  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    _db = new _SQL.Database(fileBuffer);
    console.log(`[ThreatDB] Loaded existing database from ${DB_PATH}`);
  } else {
    _db = new _SQL.Database();
    console.log("[ThreatDB] Created new in-memory database.");
  }

  // Bootstrap the schema
  _db.run(`
    CREATE TABLE IF NOT EXISTS indicators (
      id              TEXT PRIMARY KEY,
      type            TEXT NOT NULL,
      value           TEXT NOT NULL,
      reputation      TEXT NOT NULL DEFAULT 'unknown',
      confidence_score INTEGER NOT NULL DEFAULT 0,
      country         TEXT,
      sources         TEXT NOT NULL DEFAULT '[]',
      tags            TEXT NOT NULL DEFAULT '[]',
      first_seen      TEXT NOT NULL,
      last_seen       TEXT NOT NULL,
      raw_data        TEXT NOT NULL DEFAULT '{}'
    );

    -- Unique constraint prevents duplicate (type, value) combinations
    CREATE UNIQUE INDEX IF NOT EXISTS idx_indicators_type_value
      ON indicators (type, value);

    -- Index for fast reputation-based queries (e.g., GET /malicious-ips)
    CREATE INDEX IF NOT EXISTS idx_indicators_reputation
      ON indicators (reputation);

    -- Index for fast type-based filtering
    CREATE INDEX IF NOT EXISTS idx_indicators_type
      ON indicators (type);
  `);

  // Persist initial schema to disk
  persistDb(_db);

  return _db;
}

/**
 * Writes the in-memory SQL.js database to disk.
 * Called after each batch write to ensure durability.
 */
export function persistDb(db: Database): void {
  try {
    const data = db.export();
    fs.writeFileSync(DB_PATH, Buffer.from(data));
  } catch (err: any) {
    console.error("[ThreatDB] Failed to persist database:", err.message);
  }
}

/**
 * Upserts a batch of threat indicators using INSERT OR REPLACE.
 * When a (type, value) pair already exists, the row is fully replaced,
 * updating reputation, confidence, sources, tags, and last_seen.
 *
 * @param indicators - Array of normalized ThreatIndicator objects to upsert
 * @returns Number of rows actually written
 */
export async function upsertIndicators(indicators: ThreatIndicator[]): Promise<number> {
  if (indicators.length === 0) return 0;

  const db = await getDb();
  let count = 0;

  // Use a transaction for performance on large batches
  db.run("BEGIN TRANSACTION;");

  try {
    const stmt = db.prepare(`
      INSERT INTO indicators
        (id, type, value, reputation, confidence_score, country, sources, tags, first_seen, last_seen, raw_data)
      VALUES
        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(type, value) DO UPDATE SET
        reputation       = excluded.reputation,
        confidence_score = excluded.confidence_score,
        country          = excluded.country,
        sources          = excluded.sources,
        tags             = excluded.tags,
        last_seen        = excluded.last_seen,
        raw_data         = excluded.raw_data
    `);

    for (const ind of indicators) {
      stmt.run([
        ind.id,
        ind.type,
        ind.value,
        ind.reputation,
        ind.confidence_score,
        ind.country ?? null,
        ind.sources,
        ind.tags,
        ind.first_seen,
        ind.last_seen,
        ind.raw_data,
      ]);
      count++;
    }

    stmt.free();
    db.run("COMMIT;");
  } catch (err: any) {
    db.run("ROLLBACK;");
    console.error("[ThreatDB] Batch upsert failed:", err.message);
    throw err;
  }

  // Persist to disk after each batch
  persistDb(db);
  return count;
}

/**
 * Searches indicators by value (case-insensitive partial match).
 *
 * @param query - The search string (IP, domain, hash fragment, etc.)
 * @param limit - Max number of results (default 20)
 * @returns Array of raw ThreatIndicator rows
 */
export async function searchIndicators(query: string, limit = 20): Promise<ThreatIndicator[]> {
  const db = await getDb();
  const stmt = db.prepare(`
    SELECT * FROM indicators
    WHERE LOWER(value) LIKE LOWER(?)
    ORDER BY confidence_score DESC, last_seen DESC
    LIMIT ?
  `);

  const rows: ThreatIndicator[] = [];
  stmt.bind([`%${query}%`, limit]);
  while (stmt.step()) {
    rows.push(stmt.getAsObject() as unknown as ThreatIndicator);
  }
  stmt.free();
  return rows;
}

/**
 * Returns a paginated list of all indicators, optionally filtered by type and/or reputation.
 */
export async function listIndicators(opts: {
  type?: string;
  reputation?: string;
  page?: number;
  limit?: number;
}): Promise<{ rows: ThreatIndicator[]; total: number }> {
  const db = await getDb();

  const { type, reputation, page = 1, limit = 50 } = opts;
  const offset = (page - 1) * limit;

  const conditions: string[] = [];
  const params: (string | number)[] = [];

  if (type) {
    conditions.push("type = ?");
    params.push(type);
  }
  if (reputation) {
    conditions.push("reputation = ?");
    params.push(reputation);
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

  // Count query
  const countStmt = db.prepare(`SELECT COUNT(*) as cnt FROM indicators ${where}`);
  countStmt.bind(params);
  let total = 0;
  if (countStmt.step()) {
    total = (countStmt.getAsObject() as any).cnt as number;
  }
  countStmt.free();

  // Data query
  const dataStmt = db.prepare(
    `SELECT * FROM indicators ${where} ORDER BY confidence_score DESC, last_seen DESC LIMIT ? OFFSET ?`
  );
  dataStmt.bind([...params, limit, offset]);

  const rows: ThreatIndicator[] = [];
  while (dataStmt.step()) {
    rows.push(dataStmt.getAsObject() as unknown as ThreatIndicator);
  }
  dataStmt.free();

  return { rows, total };
}

/**
 * Returns all indicators with reputation = 'malicious' and type = 'IP'.
 * Used by the GET /malicious-ips endpoint.
 */
export async function getMaliciousIPs(limit = 500): Promise<ThreatIndicator[]> {
  const db = await getDb();
  const stmt = db.prepare(`
    SELECT * FROM indicators
    WHERE type = 'IP' AND reputation = 'malicious'
    ORDER BY confidence_score DESC, last_seen DESC
    LIMIT ?
  `);

  const rows: ThreatIndicator[] = [];
  stmt.bind([limit]);
  while (stmt.step()) {
    rows.push(stmt.getAsObject() as unknown as ThreatIndicator);
  }
  stmt.free();
  return rows;
}

/**
 * Returns aggregate statistics for the GET /stats endpoint.
 */
export async function getStats(): Promise<{
  total: number;
  byReputation: Record<string, number>;
  byType: Record<string, number>;
  bySource: Record<string, number>;
  lastUpdated: string | null;
}> {
  const db = await getDb();

  // Total count
  const totalRes = db.exec("SELECT COUNT(*) as cnt FROM indicators");
  const total: number = totalRes[0]?.values[0]?.[0] as number ?? 0;

  // By reputation
  const repRes = db.exec("SELECT reputation, COUNT(*) as cnt FROM indicators GROUP BY reputation");
  const byReputation: Record<string, number> = {};
  for (const row of repRes[0]?.values ?? []) {
    byReputation[row[0] as string] = row[1] as number;
  }

  // By type
  const typeRes = db.exec("SELECT type, COUNT(*) as cnt FROM indicators GROUP BY type");
  const byType: Record<string, number> = {};
  for (const row of typeRes[0]?.values ?? []) {
    byType[row[0] as string] = row[1] as number;
  }

  // Last updated (max last_seen)
  const lastRes = db.exec("SELECT MAX(last_seen) as ts FROM indicators");
  const lastUpdated: string | null = (lastRes[0]?.values[0]?.[0] as string) ?? null;

  // By source — requires parsing JSON array column; approximate with LIKE
  const sourceLabels = ["AbuseIPDB", "OTX", "Manual"];
  const bySource: Record<string, number> = {};
  for (const src of sourceLabels) {
    const srcRes = db.exec(
      `SELECT COUNT(*) as cnt FROM indicators WHERE sources LIKE '%${src}%'`
    );
    bySource[src] = (srcRes[0]?.values[0]?.[0] as number) ?? 0;
  }

  return { total, byReputation, byType, bySource, lastUpdated };
}
