import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  assertQuoteWithinCap,
  buildHubFundingActionPlan,
  normalizeIngressQuote,
  quoteResponseFromDeploymentIntentStatus
} from "../dist/funding.js";

const developer = "0x4000000000000000000000000000000000000004";
const asset = "0x0000053900000000000000000000000001200000";
const quote = {
  quoteId: `0x${"11".repeat(32)}`,
  sessionId: `0x${"22".repeat(32)}`,
  developer,
  asset,
  amount: "120000",
  minAmount: "120000",
  maxAmount: "120000",
  paidSeconds: "600",
  serviceAmount: "100000",
  setupFee: "10000",
  validationFeeCap: "10000",
  jobId: `0x${"33".repeat(32)}`,
  expectedJobSigner: "0x5000000000000000000000000000000000000005",
  operatorId: `0x${"44".repeat(32)}`,
  processorId: `0x${"55".repeat(32)}`,
  endpointHash: `0x${"66".repeat(32)}`,
  salt: `0x${"77".repeat(32)}`,
  operatorRecipient: "0x1000000000000000000000000000000000000001",
  validatorRecipient: "0x2000000000000000000000000000000000000002",
  proofRecipient: "0x3000000000000000000000000000000000000003",
  maxOperatorBps: 8000,
  maxValidatorBps: 500,
  maxProofBps: 2000,
  policyHash: `0x${"88".repeat(32)}`,
  deadline: "4102444800"
};

const binding = {
  developer,
  asset,
  paidSeconds: "600",
  expectedJobSigner: quote.expectedJobSigner,
  jobId: quote.jobId,
  operatorId: quote.operatorId,
  processorId: quote.processorId,
  salt: quote.salt
};

describe("Switchboard SDK funding helpers", () => {
  it("recovers a reusable quote from deployment-intent status", () => {
    const recovered = quoteResponseFromDeploymentIntentStatus(
      {
        ok: true,
        intent: {
          endpointHostname: "e-test.acurast.ingress.works",
          validationHostname: "v-test.acurast.ingress.works",
          allocation: { gatewayId: "gateway-a" },
          quote: {
            quote,
            signature: `0x${"aa".repeat(65)}`,
            policy: { unit: "active_endpoint_minute" }
          }
        }
      },
      binding,
      1
    );

    assert.equal(recovered?.quote.sessionId, quote.sessionId);
    assert.equal(recovered?.endpointHostname, "e-test.acurast.ingress.works");
    assert.deepEqual(recovered?.allocation, { gatewayId: "gateway-a" });
  });

  it("rejects quotes over a preview cap", () => {
    const recovered = quoteResponseFromDeploymentIntentStatus(
      { ok: true, intent: { quote: { quote, signature: `0x${"aa".repeat(65)}` } } },
      binding,
      1
    );
    assert.ok(recovered);
    assert.doesNotThrow(() => assertQuoteWithinCap(normalizeIngressQuote(quote), "120000"));
    assert.throws(
      () => assertQuoteWithinCap(normalizeIngressQuote({ ...quote, amount: "120001", maxAmount: "120001" }), "120000"),
      /exceeds preview cap/
    );
  });

  it("describes Hub funding actions without owning the signer", () => {
    const plan = buildHubFundingActionPlan({
      quote,
      signature: `0x${"aa".repeat(65)}`,
      registryAddress: "0x9000000000000000000000000000000000000009",
      developer: {
        polkadotAddress: "15sP7d6nR3nGQ7k9xYtqTjFQWfT2mJ7xv3r7GvQ9uL8mX4rK",
        contractLayerAddress: developer
      },
      accountMapped: false,
      currentAllowance: "0",
      storageDepositLimit: "1000000000000",
      weightLimit: { refTime: "10000000000", proofSize: "2000000" }
    });

    assert.deepEqual(plan.actions.map((action) => action.id), ["mapAccount", "approve", "fundWithAssetQuote"]);
    assert.match(plan.actions[1].calldata, /^0x/);
    assert.equal(plan.actions[2].to, "0x9000000000000000000000000000000000000009");
  });
});
