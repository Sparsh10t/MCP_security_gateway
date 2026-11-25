import { env } from "../config/env.js";
import { closePostgres, getPostgresPool, initPostgres } from "../services/postgres.js";
import { verifyAuditChain } from "./hashChain.js";
import { FileAuditStore, PostgresAuditStore, type AuditStore } from "./store.js";

function parseFileFlag(argv: string[]): string | undefined {
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--file" && argv[i + 1]) {
      return argv[i + 1];
    }
  }
  return undefined;
}

async function main() {
  const fileOverride = parseFileFlag(process.argv.slice(2));
  let store: AuditStore;
  let sourceLabel: string;

  if (fileOverride) {
    store = new FileAuditStore(fileOverride);
    sourceLabel = `file:${fileOverride}`;
  } else {
    const pgOk = await initPostgres();
    if (pgOk) {
      store = new PostgresAuditStore(getPostgresPool());
      sourceLabel = "postgres:audit_events";
    } else {
      store = new FileAuditStore(env.AUDIT_LOG_PATH);
      sourceLabel = `file:${env.AUDIT_LOG_PATH}`;
    }
  }

  try {
    const events = await store.getAllChronological();
    const result = verifyAuditChain(events);

    if (result.valid) {
      console.log(
        `OK [${sourceLabel}]: verified ${result.totalEvents} audit events (headHash=${result.headHash})`
      );
      process.exitCode = 0;
    } else {
      console.error(
        `TAMPER DETECTED [${sourceLabel}] at event #${result.firstInvalid?.index} (id=${result.firstInvalid?.id}): ${result.firstInvalid?.reason}`
      );
      if (result.firstInvalid?.expectedHash) {
        console.error(`  expected: ${result.firstInvalid.expectedHash}`);
        console.error(`  actual:   ${result.firstInvalid.actualHash}`);
      }
      process.exitCode = 1;
    }
  } finally {
    await closePostgres();
  }
}

main().catch((err) => {
  console.error("Audit verification failed:", err);
  process.exit(1);
});
