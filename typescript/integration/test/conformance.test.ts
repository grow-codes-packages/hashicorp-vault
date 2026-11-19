// Runs the shared conformance scenarios (conformance/scenarios) against the real service:
// core (client) and secrets (SecretsProvider over KV v2 `secret/` and KV v1 `kv1/`).
// KV v1 has no versions, so its run declares only `write` and `delete` (docs/compatibility.md).

import assert from "node:assert/strict";
import { before, test } from "node:test";
import { VaultClient, VaultSecretsProvider } from "@grow-codes/hashicorp-vault";
import { formatReport, runConformance } from "@grow-codes/hashicorp-vault/testing";
import { loadBootstrapEnv, scenariosDir } from "./env.ts";
import { env } from "./helpers.ts";

before(() => {
  loadBootstrapEnv();
});

test("conformance: core", async () => {
  const report = await runConformance({
    scenariosDir,
    categories: ["core"],
    factories: { core: () => VaultClient.fromEnv() },
    capabilities: { core: ["version"] },
  });
  console.log(formatReport(report));
  assert.equal(report.failed, 0, formatReport(report));
  assert.ok(report.passed > 0);
});

test("conformance: secrets on KV v2", async () => {
  const clients: VaultClient[] = [];
  try {
    const report = await runConformance({
      scenariosDir,
      categories: ["secrets"],
      factories: {
        secrets: () => {
          const client = VaultClient.fromEnv();
          clients.push(client);
          return client.secrets({ mount: env("VAULT_TEST_KV2_MOUNT") });
        },
      },
      capabilities: { secrets: [...VaultSecretsProvider.capabilities] },
    });
    console.log(formatReport(report));
    assert.equal(report.failed, 0, formatReport(report));
    assert.equal(report.skipped, 0, formatReport(report));
  } finally {
    await Promise.all(clients.map((c) => c.close()));
  }
});

test("conformance: secrets on KV v1", async () => {
  const clients: VaultClient[] = [];
  try {
    const report = await runConformance({
      scenariosDir,
      categories: ["secrets"],
      factories: {
        secrets: () => {
          const client = VaultClient.fromEnv();
          clients.push(client);
          return client.secrets({ mount: env("VAULT_TEST_KV1_MOUNT") });
        },
      },
      capabilities: { secrets: ["write", "delete"] },
    });
    console.log(formatReport(report));
    assert.equal(report.failed, 0, formatReport(report));
  } finally {
    await Promise.all(clients.map((c) => c.close()));
  }
});
