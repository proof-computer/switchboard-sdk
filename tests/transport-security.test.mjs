import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { SwitchboardControlPlaneClient } from "../dist/control-plane.js";
import {
  requestDeploymentIntentGroupMemberQuote,
  requestDeploymentIntentQuote,
  requestDeploymentIntentQuoteOrResume
} from "../dist/funding.js";
import {
  GATEWAY_UPSTREAM_OBSERVATION_DOMAIN,
  createEncryptedSwitchboardLogger,
  createSwitchboardRuntime,
  generateProofLogEncryptionKey,
  pollCustomerHostnameAuthorizationsWithRelay,
  registerIngressWithRelay,
  requestCertificateWithRelay
} from "../dist/index.js";

const SIGNATURE = `0x${"11".repeat(65)}`;
const JOB_SIGNER = "0x0000000000000000000000000000000000000009";
const JOB_SIGNER_PRIVATE_KEY = "0x0000000000000000000000000000000000000000000000000000000000000009";

describe("Switchboard SDK transport security", () => {
  it("rejects plaintext relay and log URLs before fetch", async () => {
    const fetchImpl = recordingFetch();

    await assert.rejects(
      () => registerIngressWithRelay(registrationConfig("http://relay.example.test"), fetchImpl),
      /Switchboard relay URL must use https:\/\//
    );
    await assert.rejects(
      () => requestCertificateWithRelay(certificateConfig("http://relay.example.test"), fetchImpl),
      /Switchboard relay URL must use https:\/\//
    );
    await assert.rejects(
      () => pollCustomerHostnameAuthorizationsWithRelay(customerHostnameConfig("http://relay.example.test"), fetchImpl),
      /Switchboard relay URL must use https:\/\//
    );

    const runtime = createSwitchboardRuntime({
      env: {
        JOB_SIGNER_PRIVATE_KEY,
        SWITCHBOARD_RELAY_URL: "http://relay.example.test",
        SWITCHBOARD_INTENT_ID: "di_test",
        SWITCHBOARD_INTENT_TOKEN: "intent-secret"
      },
      fetchImpl
    });
    await assert.rejects(() => runtime.prepare(), /SWITCHBOARD_RELAY_URL must use https:\/\//);

    const logErrors = [];
    const logger = createEncryptedSwitchboardLogger({
      logUrl: "http://logs.example.test/ingest",
      writeToken: "log-secret",
      encryptionKey: generateProofLogEncryptionKey(),
      fetchImpl,
      onError: (error) => logErrors.push(error)
    });
    await logger("transport-test");
    assert.match(String(logErrors[0]?.message ?? ""), /Switchboard log URL must use https:\/\//);

    assert.equal(fetchImpl.calls.length, 0);
  });

  it("allows HTTPS and explicit local HTTP but rejects other schemes", async () => {
    const httpsFetch = recordingFetch();
    await registerIngressWithRelay(registrationConfig("https://relay.example.test"), httpsFetch);
    assert.equal(httpsFetch.calls[0].url, "https://relay.example.test/v1/ingress-registrations");

    const localFetch = recordingFetch();
    await registerIngressWithRelay(
      { ...registrationConfig("http://127.0.0.1:3000"), allowInsecureHttp: true },
      localFetch
    );
    assert.equal(localFetch.calls[0].url, "http://127.0.0.1:3000/v1/ingress-registrations");

    await assert.rejects(
      () => registerIngressWithRelay({ ...registrationConfig("file:///tmp/relay.json"), allowInsecureHttp: true }, recordingFetch()),
      /unsupported URL protocol file:/
    );
  });

  it("applies the same guard to control-plane and funding requests", async () => {
    assert.throws(
      () => new SwitchboardControlPlaneClient({ relayUrl: "http://relay.example.test", cliToken: "cli-secret" }),
      /Switchboard control-plane relay URL must use https:\/\//
    );

    const controlFetch = recordingFetch();
    const control = new SwitchboardControlPlaneClient({
      relayUrl: "https://relay.example.test",
      cliToken: "cli-secret",
      fetchImpl: controlFetch
    });
    await control.health();
    assert.deepEqual(controlFetch.calls.map((call) => `${call.method} ${call.url}`), [
      "GET https://relay.example.test/health"
    ]);

    const fundingFetch = recordingFetch({ ok: true, quote: {}, signature: SIGNATURE });
    await requestDeploymentIntentQuote({
      relayUrl: "https://relay.example.test",
      intentId: "di_test",
      cliToken: "cli-secret",
      body: { paidSeconds: "600" },
      fetchImpl: fundingFetch
    });
    await requestDeploymentIntentGroupMemberQuote({
      relayUrl: "https://relay.example.test",
      groupId: "dig_test",
      intentId: "di_child",
      cliToken: "cli-secret",
      body: { paidSeconds: "600" },
      fetchImpl: fundingFetch
    });
    assert.deepEqual(fundingFetch.calls.map((call) => `${call.method} ${new URL(call.url).pathname}`), [
      "POST /v1/deployment-intents/di_test/quote",
      "POST /v1/deployment-intent-groups/dig_test/members/di_child/quote"
    ]);

    const statusFetch = recordingFetch();
    statusFetch.nextError = Object.assign(new Error("timed out"), { name: "TimeoutError" });
    await assert.rejects(
      () => requestDeploymentIntentQuoteOrResume({
        relayUrl: "https://relay.example.test",
        intentId: "di_test",
        cliToken: "cli-secret",
        body: { paidSeconds: "600" },
        timeoutMs: 1,
        fetchImpl: statusFetch
      }),
      /timed out/
    );
    assert.deepEqual(statusFetch.calls.map((call) => `${call.method} ${new URL(call.url).pathname}`), [
      "POST /v1/deployment-intents/di_test/quote",
      "GET /v1/deployment-intents/di_test"
    ]);

    await assert.rejects(
      () => requestDeploymentIntentQuote({
        relayUrl: "http://relay.example.test",
        intentId: "di_test",
        cliToken: "cli-secret",
        body: {},
        fetchImpl: recordingFetch()
      }),
      /Switchboard quote relay URL must use https:\/\//
    );
  });

  it("admits the gateway-observed upstream before reporting ready", async () => {
    const calls = [];
    const fetchImpl = async (url, init = {}) => {
      const parsedUrl = new URL(url.toString());
      const body = init.body ? JSON.parse(init.body.toString()) : undefined;
      calls.push({ url: parsedUrl.toString(), path: parsedUrl.pathname, method: init.method ?? "GET", body });

      if (parsedUrl.hostname === "gateway.example.test") {
        return jsonResponse({
          ok: true,
          request: body.request,
          requestSignature: body.signature,
          observation: {
            version: 1,
            kind: "switchboard.gateway-upstream-observation",
            admissionId: `0x${"aa".repeat(32)}`,
            request: body.request,
            requestDigest: `0x${"bb".repeat(32)}`,
            observedIp: "203.0.113.44",
            observedPort: 49152,
            observedAt: "2026-05-22T12:00:00.000Z",
            expiresAt: "2026-05-22T12:10:00.000Z",
            tls: {
              verified: true,
              servername: body.request.validationHostname
            }
          },
          observationSignature: {
            scheme: "eip191-secp256k1",
            domain: GATEWAY_UPSTREAM_OBSERVATION_DOMAIN,
            signer: JOB_SIGNER,
            signature: SIGNATURE,
            signedAt: "2026-05-22T12:00:00.000Z"
          }
        });
      }

      return jsonResponse({ ok: true });
    };

    const runtime = createSwitchboardRuntime({
      env: runtimeEnv({
        SWITCHBOARD_RELAY_URL: "https://relay.example.test",
        GATEWAY_UPSTREAM_ADMISSION_URL: "https://gateway.example.test/v1/upstream-admissions",
        GATEWAY_UPSTREAM_PORT: "3443"
      }),
      fetchImpl
    });

    await runtime.reportReady();

    assert.deepEqual(calls.map((call) => `${call.method} ${call.url}`), [
      "POST https://gateway.example.test/v1/upstream-admissions",
      "POST https://relay.example.test/v1/deployment-intents/di_test/upstream-admissions",
      "POST https://relay.example.test/v1/deployment-intents/di_test/health"
    ]);
    assert.equal(calls[0].body.request.upstreamPort, 3443);
    assert.equal(calls[1].body.requestSignature, calls[0].body.signature);
    assert.equal(calls[1].body.observation.observedIp, "203.0.113.44");
    assert.equal(calls[2].body.state, "ready");
    assert.equal(calls[2].body.details.gatewayUpstreamAdmission.admissionId, `0x${"aa".repeat(32)}`);
  });

  it("rejects plaintext gateway admission URLs before fetch unless explicitly opted in", async () => {
    const fetchImpl = recordingFetch();
    const runtime = createSwitchboardRuntime({
      env: runtimeEnv({
        SWITCHBOARD_RELAY_URL: "https://relay.example.test",
        GATEWAY_UPSTREAM_ADMISSION_URL: "http://gateway.example.test/v1/upstream-admissions"
      }),
      fetchImpl
    });

    await assert.rejects(
      () => runtime.admitGatewayUpstream(),
      /Switchboard gateway upstream admission URL must use https:\/\//
    );
    assert.equal(fetchImpl.calls.length, 0);
  });
});

function recordingFetch(body = { ok: true }) {
  const fetchImpl = async (url, init = {}) => {
    fetchImpl.calls.push({
      url: url.toString(),
      method: init.method ?? "GET",
      headers: init.headers ?? {}
    });
    if (fetchImpl.nextError) {
      const error = fetchImpl.nextError;
      fetchImpl.nextError = undefined;
      throw error;
    }
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  };
  fetchImpl.calls = [];
  fetchImpl.nextError = undefined;
  return fetchImpl;
}

function jsonResponse(body) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" }
  });
}

function runtimeEnv(overrides = {}) {
  return {
    JOB_SIGNER_PRIVATE_KEY,
    SWITCHBOARD_RELAY_URL: "https://relay.example.test",
    SWITCHBOARD_INTENT_ID: "di_test",
    SWITCHBOARD_INTENT_TOKEN: "intent-secret",
    SESSION_ID: hex32("01"),
    OPERATOR_ID: hex32("02"),
    PROCESSOR_ID: hex32("03"),
    GATEWAY_ID: "gateway-1",
    ENDPOINT_HOSTNAME: "demo.example.test",
    VALIDATION_HOSTNAME: "validation.demo.example.test",
    ...overrides
  };
}

function registrationConfig(relayUrl) {
  return {
    relayUrl,
    chainId: 420420419,
    registryAddress: "0x65d6B76BeC50F46D198fFa3598E381a298025Da0",
    sessionId: hex32("01"),
    jobId: hex32("02"),
    operatorId: hex32("03"),
    processorId: hex32("04"),
    endpointHostname: "demo.example.com",
    jobSigner: fakeJobSigner(),
    requestTimeoutMs: 1000
  };
}

function certificateConfig(relayUrl) {
  return {
    relayUrl,
    chainId: 420420419,
    registryAddress: "0x65d6B76BeC50F46D198fFa3598E381a298025Da0",
    sessionId: hex32("01"),
    hostname: "demo.example.com",
    csrPem: "-----BEGIN CERTIFICATE REQUEST-----\nTEST\n-----END CERTIFICATE REQUEST-----\n",
    privateKeyPem: "-----BEGIN PRIVATE KEY-----\nTEST\n-----END PRIVATE KEY-----\n",
    jobSigner: fakeJobSigner(),
    requestTimeoutMs: 1000
  };
}

function customerHostnameConfig(relayUrl) {
  return {
    relayUrl,
    intentId: "di_test",
    chainId: 420420419,
    registryAddress: "0x65d6B76BeC50F46D198fFa3598E381a298025Da0",
    sessionId: hex32("01"),
    endpointHostname: "demo.example.com",
    jobSigner: fakeJobSigner(),
    requestTimeoutMs: 1000
  };
}

function fakeJobSigner() {
  return {
    async getAddress() {
      return JOB_SIGNER;
    },
    async signRegistration() {
      return SIGNATURE;
    },
    async signCertificateRequest() {
      return SIGNATURE;
    },
    async signCustomerHostnamePollRequest() {
      return SIGNATURE;
    }
  };
}

function hex32(byte) {
  return `0x${byte.repeat(32)}`;
}
