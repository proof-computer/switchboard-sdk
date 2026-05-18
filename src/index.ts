import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { networkInterfaces } from "node:os";
import tls, { type SecureContext, type SecureContextOptions } from "node:tls";
import * as acme from "acme-client";
import { ethers } from "ethers";

export const SWITCHBOARD_CHALLENGE_PATH = "/.well-known/proofcomputer/challenge";
export const SWITCHBOARD_STATUS_PATH = "/.well-known/proofcomputer/status";
export const PROOF_INGRESS_CHALLENGE_PATH = SWITCHBOARD_CHALLENGE_PATH;
export const PROOF_INGRESS_STATUS_PATH = SWITCHBOARD_STATUS_PATH;
export const EIP712_DOMAIN_NAME = "ProofIngress";
export const EIP712_DOMAIN_VERSION = "1";
const DEFAULT_SWITCHBOARD_INTENT_REQUEST_TIMEOUT_MS = 60_000;

type SwitchboardIntentHealthState =
  | "starting"
  | "claimed"
  | "waiting_quote"
  | "waiting_funding"
  | "config_received"
  | "registering"
  | "registered"
  | "certificate_requesting"
  | "ready"
  | "failed";

export interface SwitchboardChallengeConfig {
  sessionId: string | (() => string);
  deploymentId?: string;
  jobId?: string | (() => string | undefined);
  onChallenge?: (event: SwitchboardChallengeEvent) => void | Promise<void>;
}

export interface SwitchboardChallengeEvent {
  nonce: string;
  timestamp: number;
  path: string;
  userAgent?: string;
  remoteAddress?: string;
}

export interface SwitchboardChallengeRequest {
  nonce: unknown;
  path: string;
  userAgent?: string;
  remoteAddress?: string;
}

export interface SwitchboardChallengeResponse {
  sessionId: string;
  nonce: string;
  deploymentId?: string;
  jobId?: string;
  timestamp: number;
}

export interface SwitchboardChallengeError {
  error: "missing_nonce";
}

export interface SwitchboardChallengeResult {
  statusCode: number;
  headers: Record<string, string>;
  body: SwitchboardChallengeResponse | SwitchboardChallengeError;
}

export interface RegistrationPayload {
  sessionId: string;
  jobId: string;
  jobSigner: string;
  operatorId: string;
  processorId: string;
  endpointHash: string;
  nonce: string | bigint | number;
  deadline: string | bigint | number;
}

export interface CertificateRequestPayload {
  sessionId: string;
  jobSigner: string;
  hostname: string;
  csrHash: string;
  nonce: string | bigint | number;
  deadline: string | bigint | number;
}

export interface CustomerHostnamePollRequestPayload {
  sessionId: string;
  jobSigner: string;
  endpointHostname: string;
  nonce: string | bigint | number;
  deadline: string | bigint | number;
}

export interface SwitchboardJobSigner {
  getAddress(): Promise<string>;
  signRegistration(input: {
    chainId: string | number | bigint;
    registryAddress: string;
    registration: RegistrationPayload;
  }): Promise<string>;
  signCertificateRequest(input: {
    chainId: string | number | bigint;
    registryAddress: string;
    certificateRequest: CertificateRequestPayload;
  }): Promise<string>;
  signCustomerHostnamePollRequest?(input: {
    chainId: string | number | bigint;
    registryAddress: string;
    request: CustomerHostnamePollRequestPayload;
  }): Promise<string>;
}

export interface AcurastRuntimeStd {
  env?: Record<string, string | undefined>;
  job?: {
    getId?: () => unknown;
    getProcessorId?: () => unknown;
    getPublicKeys?: () => unknown;
  };
  device?: {
    getAddress?: () => unknown;
  };
  net?: {
    addAllowedHostnames?: (hostnames: string[]) => unknown;
  };
  signers?: {
    secp256k1?: {
      sign?: (payload: string) => string | Promise<string>;
    };
  };
}

export interface SwitchboardRegistrationConfig {
  relayUrl: string;
  chainId: string | number | bigint;
  registryAddress: string;
  sessionId: string;
  jobId: string;
  operatorId: string;
  processorId: string;
  endpointHostname?: string;
  endpointHash?: string;
  nonce?: string | number | bigint;
  deadline?: string | number | bigint;
  jobSigner?: SwitchboardJobSigner;
  jobSignerPrivateKey?: string;
  requestTimeoutMs?: number;
}

export interface SwitchboardCertificateConfig {
  relayUrl: string;
  chainId: string | number | bigint;
  registryAddress: string;
  sessionId: string;
  hostname: string;
  csrPem?: string;
  privateKeyPem?: string;
  nonce?: string | number | bigint;
  deadline?: string | number | bigint;
  jobSigner?: SwitchboardJobSigner;
  jobSignerPrivateKey?: string;
  requestTimeoutMs?: number;
}

export interface SwitchboardRegistrationRequest {
  registration: RegistrationPayload;
  signature: string;
}

export interface SwitchboardRegistrationResult extends SwitchboardRegistrationRequest {
  relayResponse: unknown;
}

export interface SwitchboardCertificateSigningRequest {
  privateKeyPem: string;
  csrPem: string;
}

export interface SwitchboardCertificateRelayRequest {
  certificateRequest: CertificateRequestPayload;
  csrPem: string;
  signature: string;
}

export interface SwitchboardCertificateResult extends SwitchboardCertificateRelayRequest {
  privateKeyPem?: string;
  relayResponse: {
    hostname?: string;
    certificatePem?: string;
    issuer?: string;
    notAfter?: string;
    [key: string]: unknown;
  };
}

export interface SwitchboardCustomerHostnamePollRelayRequest {
  request: CustomerHostnamePollRequestPayload;
  signature: string;
}

export interface SwitchboardCustomerHostnameAuthorization {
  customerHostname: string;
  endpointHostname: string;
  sessionId?: string;
  sessionIds?: string[];
  developer?: string;
  status?: string;
  certificate?: Record<string, unknown>;
  developerAuthorization?: Record<string, unknown>;
}

export interface SwitchboardCustomerHostnamePollResponse {
  ok: boolean;
  intentId?: string;
  checkedAt?: string;
  request?: CustomerHostnamePollRequestPayload;
  developer?: string;
  session?: Record<string, unknown>;
  hostnames?: string[];
  authorizations?: SwitchboardCustomerHostnameAuthorization[];
  [key: string]: unknown;
}

export interface SwitchboardCustomerHostnamePollConfig {
  relayUrl: string;
  intentId: string;
  chainId: string | number | bigint;
  registryAddress: string;
  sessionId: string;
  endpointHostname: string;
  nonce?: string | number | bigint;
  deadline?: string | number | bigint;
  jobSigner?: SwitchboardJobSigner;
  jobSignerPrivateKey?: string;
  requestTimeoutMs?: number;
}

export interface SwitchboardManagedCertificate {
  hostname: string;
  cert: string;
  key: string;
  issuer?: string;
  notAfter?: string;
}

export type SwitchboardCertificateFailureStage =
  | "hostname_config"
  | "certificate_lock"
  | "certificate_request"
  | "certificate_authorization"
  | "acme_issuance"
  | "relay_response";

export interface SwitchboardCertificateErrorOptions {
  stage: SwitchboardCertificateFailureStage;
  hostname?: string;
  status?: number;
  relayResponse?: unknown;
  cause?: unknown;
}

export class SwitchboardCertificateError extends Error {
  readonly stage: SwitchboardCertificateFailureStage;
  readonly hostname: string | undefined;
  readonly status: number | undefined;
  readonly relayResponse: unknown;

  constructor(message: string, options: SwitchboardCertificateErrorOptions) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "SwitchboardCertificateError";
    this.stage = options.stage;
    this.hostname = options.hostname;
    this.status = options.status;
    this.relayResponse = options.relayResponse;
  }
}

export interface SwitchboardRuntimeConfig {
  relayUrl?: string;
  chainId?: string;
  registryAddress?: string;
  sessionId?: string;
  jobId?: string;
  operatorId?: string;
  processorId?: string;
  gatewayId?: string;
  endpointHostname?: string;
  certificateMode?: string;
  certificateHostnames?: string[];
}

export interface SwitchboardRuntimeConfigResponse {
  ok: boolean;
  state?: string;
  intent?: Record<string, unknown>;
  config?: SwitchboardRuntimeConfig;
}

export interface SwitchboardRuntimeOptions {
  env?: NodeJS.ProcessEnv;
  std?: AcurastRuntimeStd;
  fetchImpl?: typeof fetch;
  deploymentId?: string;
  initialConfig?: Record<string, string>;
  onError?: (error: unknown, event: string) => void;
}

export interface SwitchboardRuntimePrepareResult {
  certificates: SwitchboardManagedCertificate[];
  tlsOptions?: SwitchboardTlsOptions;
  registration?: SwitchboardRegistrationResult;
}

export type SwitchboardTlsOptions = SecureContextOptions & {
  SNICallback?: (servername: string, callback: (error: Error | null, context?: SecureContext) => void) => void;
};

export interface SwitchboardLogRecord {
  timestamp: string;
  event: string;
  context?: string;
  sessionId?: string;
  jobId?: string;
  deploymentId?: string;
  runtime?: Record<string, unknown>;
  details?: Record<string, unknown>;
}

export interface SwitchboardRemoteLoggerConfig {
  logUrl?: string;
  writeToken?: string;
  encryptionKey?: string;
  context?: string;
  timeoutMs?: number;
  baseRecord?: () => Record<string, unknown>;
  onError?: (error: unknown, event: string) => void;
  fetchImpl?: typeof fetch;
}

export interface ProofLogEncryptedRecord {
  v: 1;
  alg: "A256GCM";
  iv: string;
  ciphertext: string;
  tag: string;
}

export type ProofIngressChallengeConfig = SwitchboardChallengeConfig;
export type ProofIngressChallengeEvent = SwitchboardChallengeEvent;
export type ProofIngressChallengeRequest = SwitchboardChallengeRequest;
export type ProofIngressChallengeResponse = SwitchboardChallengeResponse;
export type ProofIngressChallengeResult = SwitchboardChallengeResult;
export type ProofIngressJobSigner = SwitchboardJobSigner;
export type ProofIngressRegistrationConfig = SwitchboardRegistrationConfig;
export type ProofIngressCertificateConfig = SwitchboardCertificateConfig;
export type ProofIngressManagedCertificate = SwitchboardManagedCertificate;
export type ProofIngressRuntimeConfig = SwitchboardRuntimeConfig;
export type ProofIngressRuntimeOptions = SwitchboardRuntimeOptions;
export type ProofIngressRuntimePrepareResult = SwitchboardRuntimePrepareResult;
export type ProofIngressLogRecord = SwitchboardLogRecord;
export type ProofIngressRemoteLoggerConfig = SwitchboardRemoteLoggerConfig;

export const REGISTRATION_TYPES: Record<string, Array<{ name: string; type: string }>> = {
  Registration: [
    { name: "sessionId", type: "bytes32" },
    { name: "jobId", type: "bytes32" },
    { name: "jobSigner", type: "address" },
    { name: "operatorId", type: "bytes32" },
    { name: "processorId", type: "bytes32" },
    { name: "endpointHash", type: "bytes32" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" }
  ]
};

export const CERTIFICATE_REQUEST_TYPES: Record<string, Array<{ name: string; type: string }>> = {
  CertificateRequest: [
    { name: "sessionId", type: "bytes32" },
    { name: "jobSigner", type: "address" },
    { name: "hostname", type: "string" },
    { name: "csrHash", type: "bytes32" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" }
  ]
};

export const CUSTOMER_HOSTNAME_POLL_DOMAIN_NAME = "SwitchboardCustomerHostnamePoll";
export const CUSTOMER_HOSTNAME_POLL_DOMAIN_VERSION = "1";

export const CUSTOMER_HOSTNAME_POLL_REQUEST_TYPES: Record<string, Array<{ name: string; type: string }>> = {
  CustomerHostnamePollRequest: [
    { name: "sessionId", type: "bytes32" },
    { name: "jobSigner", type: "address" },
    { name: "endpointHostname", type: "string" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" }
  ]
};

export class SwitchboardRuntime {
  readonly deploymentId: string | undefined;
  private readonly env: NodeJS.ProcessEnv;
  private readonly std?: AcurastRuntimeStd;
  private readonly fetchImpl: typeof fetch;
  private readonly runtimeConfig: Record<string, string>;
  private readonly logEvent: (event: string, details?: Record<string, unknown>) => Promise<void>;
  private readonly managedCertificates: SwitchboardManagedCertificate[] = [];
  private readonly managedCertificateContexts = new Map<string, SecureContext>();
  private customerHostnamePollTimer?: NodeJS.Timeout;
  private customerHostnamePollActive = false;
  private customerHostnamePollStopped = false;

  constructor(options: SwitchboardRuntimeOptions = {}) {
    this.env = options.env ?? process.env;
    this.std = options.std ?? (globalThis as { _STD_?: AcurastRuntimeStd })._STD_;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.runtimeConfig = {
      ...readSwitchboardConfig(options.env ?? process.env, this.std),
      ...(options.initialConfig ?? {})
    };
    const rawDeploymentId = options.deploymentId ?? this.env.DEPLOYMENT_ID ?? acurastDeploymentId(this.std);
    this.deploymentId = acurastDeploymentSequence(rawDeploymentId) ?? rawDeploymentId;
    this.logEvent = createEncryptedSwitchboardLogger({
      logUrl: this.configValue("SWITCHBOARD_LOG_URL"),
      writeToken: this.configValue("SWITCHBOARD_LOG_TOKEN"),
      encryptionKey: this.configValue("SWITCHBOARD_LOG_ENCRYPTION_KEY"),
      timeoutMs: numberConfig(this, "SWITCHBOARD_LOG_TIMEOUT_MS", 5_000),
      context: this.configValue("SWITCHBOARD_LOG_CONTEXT"),
      fetchImpl: this.fetchImpl,
      onError: options.onError,
      baseRecord: () => ({
        sessionId: this.sessionId(),
        jobId: this.jobId(),
        deploymentId: this.deploymentId,
        runtime: runtimeSummary(this.std)
      })
    });
  }

  configValue(name: string): string | undefined {
    for (const candidate of configNameCandidates(name)) {
      const value = this.runtimeConfig[candidate] ?? envValue(candidate, this.env, this.std);
      if (value) {
        return value;
      }
    }
    return undefined;
  }

  setRuntimeConfig(values: Record<string, string | undefined>): void {
    for (const [key, value] of Object.entries(values)) {
      if (value !== undefined) {
        this.runtimeConfig[key] = value;
      }
    }
  }

  sessionId(): string {
    return this.configValue("SESSION_ID") ?? "local-session";
  }

  jobId(): string | undefined {
    return this.configValue("JOB_ID");
  }

  intentConfigured(): boolean {
    return Boolean(
      this.configValue("SWITCHBOARD_RELAY_URL") &&
      this.configValue("SWITCHBOARD_INTENT_ID") &&
      this.configValue("SWITCHBOARD_INTENT_TOKEN")
    );
  }

  groupIntentConfigured(): boolean {
    return Boolean(
      this.configValue("SWITCHBOARD_RELAY_URL") &&
      this.configValue("SWITCHBOARD_INTENT_GROUP_ID") &&
      this.configValue("SWITCHBOARD_INTENT_TOKEN")
    );
  }

  async log(event: string, details: Record<string, unknown> = {}): Promise<void> {
    await this.logEvent(event, details);
  }

  async prepare(): Promise<SwitchboardRuntimePrepareResult> {
    await this.log("process-start", {
      argv: process.argv.slice(0, 2).map((value) => value.split("/").pop())
    });
    await this.logJobSignerReady();

    if (this.groupIntentConfigured()) {
      return this.prepareFromDeploymentIntentGroup();
    }

    if (this.intentConfigured()) {
      return this.prepareFromDeploymentIntent();
    }

    if (this.configValue("SWITCHBOARD_AUTO_REGISTER") === "false") {
      return { certificates: [] };
    }

    if (requiredRegistrationEnv().every((name) => this.configValue(name))) {
      const registration = await this.registerIngress(1);
      const certificates = await this.requestCertificates();
      return { ...this.prepareManagedCertificateResult(certificates), registration };
    }

    return { certificates: [] };
  }

  private async prepareFromDeploymentIntentGroup(): Promise<SwitchboardRuntimePrepareResult> {
    const relayUrl = this.requiredConfig("SWITCHBOARD_RELAY_URL");
    const groupId = this.requiredConfig("SWITCHBOARD_INTENT_GROUP_ID");
    const intentToken = this.requiredConfig("SWITCHBOARD_INTENT_TOKEN");
    allowAcurastHostname(relayUrl, this.std);

    const signer = await this.jobSigner();
    const runtimeSigner = await signer.signer.getAddress();
    const processorIdentity = acurastProcessorIdentity(this.std);
    const claimed = await this.claimIntentGroup({
      relayUrl,
      groupId,
      intentToken,
      runtimeSigner,
      signerMode: signer.mode,
      processorIdentity
    });
    const intentId =
      stringRecordField(claimed, "intentId") ??
      stringRecordField(claimed.intent, "intentId");
    if (!intentId) {
      throw new Error("Switchboard group claim response did not include a child intentId");
    }
    this.setRuntimeConfig({
      SWITCHBOARD_INTENT_ID: intentId,
      SWITCHBOARD_INTENT_TOKEN: intentToken
    });
    return this.prepareFromDeploymentIntent();
  }

  async reportReady(details: Record<string, unknown> = {}): Promise<void> {
    if (!this.intentConfigured()) {
      return;
    }
    await this.reportIntentHealthBestEffort("ready", {
      sessionId: this.sessionId(),
      endpointHostname: this.configValue("ENDPOINT_HOSTNAME"),
      ...details
    });
  }

  private async prepareFromDeploymentIntent(): Promise<SwitchboardRuntimePrepareResult> {
    const relayUrl = this.requiredConfig("SWITCHBOARD_RELAY_URL");
    const intentId = this.requiredConfig("SWITCHBOARD_INTENT_ID");
    const intentToken = this.requiredConfig("SWITCHBOARD_INTENT_TOKEN");
    allowAcurastHostname(relayUrl, this.std);

    const signer = await this.jobSigner();
    const runtimeSigner = await signer.signer.getAddress();
    await this.claimIntent({ relayUrl, intentId, intentToken, runtimeSigner, signerMode: signer.mode });
    await this.reportIntentHealthBestEffort("waiting_funding", { runtimeSigner });

    const retryMs = numberConfig(this, "SWITCHBOARD_INTENT_POLL_MS", numberConfig(this, "SWITCHBOARD_REGISTRATION_RETRY_MS", 30_000));
    const maxAttempts = numberConfig(this, "SWITCHBOARD_INTENT_MAX_ATTEMPTS", 0);

    for (let attempt = 1; maxAttempts === 0 || attempt <= maxAttempts; attempt += 1) {
      try {
        const runtime = await this.fetchRuntimeConfig(relayUrl, intentId, intentToken);
        const gatewayId = gatewayIdFromRuntimeResponse(runtime);
        if (gatewayId) {
          this.setRuntimeConfig({ GATEWAY_ID: gatewayId });
        }
        if (!runtime.ok) {
          await this.log("deployment-intent-waiting", {
            attempt,
            state: runtime.state,
            intent: runtime.intent
          });
          await this.reportIntentHealthBestEffort(runtime.state === "waiting_quote" ? "waiting_quote" : "waiting_funding", { attempt });
          await sleep(retryMs);
          continue;
        }
        if (!runtime.config) {
          throw new Error("Switchboard runtime config response missing config");
        }

        this.applySwitchboardRuntimeConfig(runtime.config);
        await this.reportIntentHealthBestEffort("config_received", {
          sessionId: this.sessionId(),
          endpointHostname: this.configValue("ENDPOINT_HOSTNAME")
        });
        const registration = await this.registerIngress(attempt);
        await this.reportIntentHealthBestEffort("registered", { sessionId: this.sessionId() });
        const certificates = await this.requestCertificates();
        return { ...this.prepareManagedCertificateResult(certificates), registration };
      } catch (error) {
        const willRetry = maxAttempts === 0 || attempt < maxAttempts;
        await this.log("deployment-intent-loop-failed", {
          attempt,
          maxAttempts,
          retryMs: willRetry ? retryMs : undefined,
          error: safeError(error)
        });
        await this.reportIntentHealth(willRetry ? "waiting_funding" : "failed", {
          attempt,
          error: error instanceof Error ? error.message : String(error)
        }).catch(() => undefined);
        if (!willRetry) {
          throw error;
        }
        await sleep(retryMs);
      }
    }

    return { certificates: [] };
  }

  private async logJobSignerReady(): Promise<void> {
    try {
      const signer = await this.jobSigner();
      await this.log("job-signer-ready", {
        signerMode: signer.mode,
        jobSigner: await signer.signer.getAddress()
      });
    } catch (error) {
      await this.log("job-signer-unavailable", { error: safeError(error) });
    }
  }

  private async jobSigner(): Promise<{ signer: SwitchboardJobSigner; mode: string }> {
    const privateKey = this.configValue("JOB_SIGNER_PRIVATE_KEY");
    if (privateKey) {
      return { signer: privateKeyJobSigner(privateKey), mode: "private-key" };
    }
    const acurastSigner = maybeAcurastJobSigner(this.std);
    if (acurastSigner) {
      return { signer: acurastSigner, mode: "acurast-secp256k1" };
    }
    throw new Error("Missing JOB_SIGNER_PRIVATE_KEY and Acurast secp256k1 runtime signer");
  }

  private async claimIntent(input: {
    relayUrl: string;
    intentId: string;
    intentToken: string;
    runtimeSigner: string;
    signerMode: string;
  }): Promise<void> {
    const response = await this.intentFetch(input, "claim", {
      runtimeSigner: input.runtimeSigner,
      acurastJobId: acurastDeploymentId(this.std),
      acurastDeploymentId: this.deploymentId,
      signerMode: input.signerMode,
      upstreamIps: publicNetworkAddresses(),
      source: { runtime: runtimeSummary(this.std) }
    });
    await this.log("deployment-intent-claimed", {
      intentId: input.intentId,
      runtimeSigner: input.runtimeSigner,
      response
    });
  }

  private async claimIntentGroup(input: {
    relayUrl: string;
    groupId: string;
    intentToken: string;
    runtimeSigner: string;
    signerMode: string;
    processorIdentity: AcurastProcessorIdentity;
  }): Promise<Record<string, unknown>> {
    const response = await this.fetchImpl(new URL(`/v1/deployment-intent-groups/${encodeURIComponent(input.groupId)}/claim`, input.relayUrl), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${input.intentToken}`
      },
      body: JSON.stringify({
        runtimeSigner: input.runtimeSigner,
        acurastJobId: acurastDeploymentId(this.std),
        acurastDeploymentId: this.deploymentId,
        signerMode: input.signerMode,
        upstreamIps: publicNetworkAddresses(),
        processorId: input.processorIdentity.processorId,
        processor: input.processorIdentity.processor,
        processorAddress: input.processorIdentity.address,
        processorIdentity: input.processorIdentity,
        source: { runtime: runtimeSummary(this.std) }
      }),
      signal: AbortSignal.timeout(this.intentRequestTimeoutMs())
    });
    const responseBody = (await response.json()) as Record<string, unknown>;
    if (!response.ok) {
      throw new Error(`Switchboard intent group claim failed: ${response.status} ${JSON.stringify(responseBody)}`);
    }
    await this.log("deployment-intent-group-claimed", {
      groupId: input.groupId,
      runtimeSigner: input.runtimeSigner,
      processorIdentity: input.processorIdentity,
      response: responseBody
    });
    return responseBody;
  }

  private async reportIntentHealth(
    state: SwitchboardIntentHealthState,
    details: Record<string, unknown> = {}
  ): Promise<void> {
    await this.intentFetch(
      {
        relayUrl: this.requiredConfig("SWITCHBOARD_RELAY_URL"),
        intentId: this.requiredConfig("SWITCHBOARD_INTENT_ID"),
        intentToken: this.requiredConfig("SWITCHBOARD_INTENT_TOKEN")
      },
      "health",
      { state, details }
    );
  }

  private async reportIntentHealthBestEffort(
    state: SwitchboardIntentHealthState,
    details: Record<string, unknown> = {}
  ): Promise<void> {
    try {
      await this.reportIntentHealth(state, details);
    } catch (error) {
      await this.log("deployment-intent-health-report-failed", {
        state,
        error: safeError(error)
      }).catch(() => undefined);
    }
  }

  private async fetchRuntimeConfig(
    relayUrl: string,
    intentId: string,
    intentToken: string
  ): Promise<SwitchboardRuntimeConfigResponse> {
    const response = await this.fetchImpl(new URL(`/v1/deployment-intents/${encodeURIComponent(intentId)}/runtime-config`, relayUrl), {
      method: "GET",
      headers: { authorization: `Bearer ${intentToken}` },
      signal: AbortSignal.timeout(this.intentRequestTimeoutMs())
    });
    const body = (await response.json()) as SwitchboardRuntimeConfigResponse;
    if (response.status === 202) {
      return body;
    }
    if (!response.ok || !body.ok) {
      throw new Error(`Switchboard runtime config failed: ${response.status} ${JSON.stringify(body)}`);
    }
    return body;
  }

  private async intentFetch(
    input: { relayUrl: string; intentId: string; intentToken: string },
    endpoint: "claim" | "health",
    body: Record<string, unknown>
  ): Promise<Record<string, unknown>> {
    const response = await this.fetchImpl(new URL(`/v1/deployment-intents/${encodeURIComponent(input.intentId)}/${endpoint}`, input.relayUrl), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${input.intentToken}`
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(this.intentRequestTimeoutMs())
    });
    const responseBody = (await response.json()) as Record<string, unknown>;
    if (!response.ok) {
      throw new Error(`Switchboard intent ${endpoint} failed: ${response.status} ${JSON.stringify(responseBody)}`);
    }
    return responseBody;
  }

  private applySwitchboardRuntimeConfig(config: SwitchboardRuntimeConfig): void {
    this.setRuntimeConfig({
      RELAY_URL: requiredRuntimeConfig(config.relayUrl, "relayUrl"),
      CHAIN_ID: requiredRuntimeConfig(config.chainId, "chainId"),
      INGRESS_REGISTRY_ADDRESS: requiredRuntimeConfig(config.registryAddress, "registryAddress"),
      SESSION_ID: requiredRuntimeConfig(config.sessionId, "sessionId"),
      JOB_ID: requiredRuntimeConfig(config.jobId, "jobId"),
      OPERATOR_ID: requiredRuntimeConfig(config.operatorId, "operatorId"),
      PROCESSOR_ID: requiredRuntimeConfig(config.processorId, "processorId"),
      GATEWAY_ID: config.gatewayId,
      ENDPOINT_HOSTNAME: requiredRuntimeConfig(config.endpointHostname, "endpointHostname"),
      SWITCHBOARD_CERTIFICATE_MODE: config.certificateMode ?? "job-acme",
      SWITCHBOARD_CERTIFICATE_HOSTNAMES: (config.certificateHostnames ?? [config.endpointHostname]).filter(Boolean).join(",")
    });
  }

  private async registerIngress(attempt: number): Promise<SwitchboardRegistrationResult> {
    const signer = await this.jobSigner();
    await this.reportIntentHealth("registering", { attempt }).catch(() => undefined);
    const result = await registerIngressWithRelay({
      relayUrl: this.requiredConfig("RELAY_URL"),
      chainId: this.requiredConfig("CHAIN_ID"),
      registryAddress: this.requiredConfig("INGRESS_REGISTRY_ADDRESS"),
      sessionId: this.requiredConfig("SESSION_ID"),
      jobId: this.requiredConfig("JOB_ID"),
      operatorId: this.requiredConfig("OPERATOR_ID"),
      processorId: this.requiredConfig("PROCESSOR_ID"),
      endpointHostname: this.requiredConfig("ENDPOINT_HOSTNAME"),
      nonce: this.configValue("NONCE"),
      deadline: this.configValue("DEADLINE"),
      jobSigner: signer.signer,
      requestTimeoutMs: numberConfig(this, "CONTRACT_CALL_TIMEOUT_MS", 120_000)
    }, this.fetchImpl);
    await this.log("registration-succeeded", {
      attempt,
      signerMode: signer.mode,
      relayResponse: sanitizeRelayResponse(result.relayResponse)
    });
    return result;
  }

  private async requestCertificates(hostnames = this.certificateHostnames()): Promise<SwitchboardManagedCertificate[]> {
    if (this.configValue("SWITCHBOARD_CERTIFICATE_MODE") !== "job-acme") {
      return [];
    }
    if (hostnames.length === 0) {
      throw new SwitchboardCertificateError("Switchboard job-acme certificate request has no certificate hostnames", {
        stage: "hostname_config"
      });
    }
    const retryMs = numberConfig(this, "SWITCHBOARD_CERTIFICATE_RETRY_MS", numberConfig(this, "SWITCHBOARD_REGISTRATION_RETRY_MS", 30_000));
    const maxAttempts = numberConfig(this, "SWITCHBOARD_CERTIFICATE_MAX_ATTEMPTS", 0);

    for (let attempt = 1; maxAttempts === 0 || attempt <= maxAttempts; attempt += 1) {
      try {
        await this.reportIntentHealth("certificate_requesting", {
          attempt,
          stage: "certificate_request",
          hostnames
        }).catch(() => undefined);
        const signer = await this.jobSigner();
        const certificates: SwitchboardManagedCertificate[] = [];
        for (const hostname of hostnames) {
          await this.log("certificate-request-started", {
            attempt,
            hostname,
            endpointHostname: this.configValue("ENDPOINT_HOSTNAME"),
            relayHost: safeUrlHost(this.requiredConfig("RELAY_URL")),
            signerMode: signer.mode,
            jobSigner: await signer.signer.getAddress()
          });
          let result: SwitchboardCertificateResult;
          try {
            result = await requestCertificateWithRelay({
              relayUrl: this.requiredConfig("RELAY_URL"),
              chainId: this.requiredConfig("CHAIN_ID"),
              registryAddress: this.requiredConfig("INGRESS_REGISTRY_ADDRESS"),
              sessionId: this.requiredConfig("SESSION_ID"),
              hostname,
              jobSigner: signer.signer,
              requestTimeoutMs: numberConfig(this, "SWITCHBOARD_CERTIFICATE_REQUEST_TIMEOUT_MS", 120_000)
            }, this.fetchImpl);
          } catch (error) {
            throw asSwitchboardCertificateError(error, {
              stage: "certificate_request",
              hostname
            });
          }
          const cert = result.relayResponse.certificatePem;
          if (!cert || !result.privateKeyPem) {
            throw new SwitchboardCertificateError(`Relay certificate response did not include certificatePem or local privateKeyPem for ${hostname}`, {
              stage: "relay_response",
              hostname,
              relayResponse: result.relayResponse
            });
          }
          certificates.push({
            hostname,
            cert,
            key: result.privateKeyPem,
            issuer: typeof result.relayResponse.issuer === "string" ? result.relayResponse.issuer : undefined,
            notAfter: typeof result.relayResponse.notAfter === "string" ? result.relayResponse.notAfter : undefined
          });
        }
        await this.log("certificate-issued", {
          attempt,
          hostnames: certificates.map((certificate) => certificate.hostname),
          certificates: certificates.map((certificate) => ({
            hostname: certificate.hostname,
            issuer: certificate.issuer,
            notAfter: certificate.notAfter
          }))
        });
        return certificates;
      } catch (error) {
        const willRetry = maxAttempts === 0 || attempt < maxAttempts;
        const certificateError = asSwitchboardCertificateError(error, {
          stage: "certificate_request"
        });
        const retryAfterMs = certificateRetryAfterMs(certificateError);
        const nextRetryMs = retryAfterMs ?? retryMs;
        const errorDetails = switchboardCertificateErrorDetails(certificateError);
        await this.log("certificate-request-failed", {
          attempt,
          maxAttempts,
          retryMs: willRetry ? nextRetryMs : undefined,
          ...errorDetails
        });
        await this.reportIntentHealth(willRetry ? "certificate_requesting" : "failed", {
          attempt,
          maxAttempts,
          retryMs: willRetry ? nextRetryMs : undefined,
          retryExhausted: !willRetry,
          ...errorDetails
        }).catch(() => undefined);
        if (!willRetry) {
          throw certificateError;
        }
        await sleep(nextRetryMs);
      }
    }

    return [];
  }

  private prepareManagedCertificateResult(certificates: SwitchboardManagedCertificate[]): SwitchboardRuntimePrepareResult {
    this.replaceManagedCertificates(certificates);
    this.startCustomerHostnamePolling();
    return {
      certificates: this.managedCertificates,
      tlsOptions: this.tlsOptionsForManagedCertificates()
    };
  }

  private replaceManagedCertificates(certificates: SwitchboardManagedCertificate[]): void {
    this.managedCertificates.splice(0, this.managedCertificates.length);
    this.managedCertificateContexts.clear();
    for (const certificate of certificates) {
      this.addManagedCertificate(certificate);
    }
  }

  private addManagedCertificate(certificate: SwitchboardManagedCertificate): boolean {
    const hostname = normalizeHostname(certificate.hostname);
    const existingIndex = this.managedCertificates.findIndex((item) => normalizeHostname(item.hostname) === hostname);
    if (existingIndex >= 0) {
      this.managedCertificates[existingIndex] = certificate;
    } else {
      this.managedCertificates.push(certificate);
    }
    this.managedCertificateContexts.set(
      hostname,
      tls.createSecureContext({
        cert: certificate.cert,
        key: certificate.key
      })
    );
    return existingIndex < 0;
  }

  private tlsOptionsForManagedCertificates(): SwitchboardTlsOptions | undefined {
    if (this.managedCertificates.length === 0) {
      return undefined;
    }
    const defaultCertificate = this.managedCertificates[0]!;
    return {
      cert: defaultCertificate.cert,
      key: defaultCertificate.key,
      SNICallback: (servername, callback) => {
        const context =
          this.managedCertificateContexts.get(normalizeHostname(servername)) ??
          this.managedCertificateContexts.get(normalizeHostname(defaultCertificate.hostname));
        if (!context) {
          callback(new Error("No TLS context available"));
          return;
        }
        callback(null, context);
      }
    };
  }

  private startCustomerHostnamePolling(): void {
    if (this.customerHostnamePollTimer || this.customerHostnamePollStopped) {
      return;
    }
    if (this.configValue("SWITCHBOARD_CERTIFICATE_MODE") !== "job-acme") {
      return;
    }
    if (
      !this.configValue("SWITCHBOARD_INTENT_ID") ||
      !(this.configValue("SWITCHBOARD_RELAY_URL") ?? this.configValue("RELAY_URL")) ||
      !this.configValue("ENDPOINT_HOSTNAME")
    ) {
      return;
    }
    const durationMs = numberConfig(this, "SWITCHBOARD_CUSTOMER_HOSTNAME_POLL_DURATION_MS", 15 * 60_000);
    if (durationMs <= 0) {
      return;
    }
    const intervalMs = Math.max(1_000, numberConfig(this, "SWITCHBOARD_CUSTOMER_HOSTNAME_POLL_MS", 10_000));
    const deadlineMs = Date.now() + durationMs;
    const tick = () => {
      if (Date.now() >= deadlineMs) {
        this.stopCustomerHostnamePolling();
        return;
      }
      void this.pollCustomerHostnameAuthorizationsOnce().then((issued) => {
        if (issued && this.configValue("SWITCHBOARD_CUSTOMER_HOSTNAME_POLL_STOP_AFTER_SUCCESS") !== "false") {
          this.stopCustomerHostnamePolling();
        }
      });
    };
    void this.log("customer-hostname-poll-started", { intervalMs, durationMs }).catch(() => undefined);
    this.customerHostnamePollTimer = setInterval(tick, intervalMs);
    this.customerHostnamePollTimer.unref();
    tick();
  }

  private stopCustomerHostnamePolling(): void {
    if (this.customerHostnamePollTimer) {
      clearInterval(this.customerHostnamePollTimer);
      this.customerHostnamePollTimer = undefined;
    }
    this.customerHostnamePollStopped = true;
  }

  private async pollCustomerHostnameAuthorizationsOnce(): Promise<boolean> {
    if (this.customerHostnamePollActive) {
      return false;
    }
    this.customerHostnamePollActive = true;
    try {
      const relayUrl = this.configValue("SWITCHBOARD_RELAY_URL") ?? this.configValue("RELAY_URL");
      const intentId = this.configValue("SWITCHBOARD_INTENT_ID");
      const endpointHostname = this.configValue("ENDPOINT_HOSTNAME");
      if (!relayUrl || !intentId || !endpointHostname) {
        return false;
      }
      const signer = await this.jobSigner();
      const jobSigner = signer.signer;
      if (typeof jobSigner.signCustomerHostnamePollRequest !== "function") {
        await this.log("customer-hostname-poll-skipped", {
          reason: "job-signer-does-not-support-customer-hostname-poll"
        }).catch(() => undefined);
        this.stopCustomerHostnamePolling();
        return false;
      }
      const response = await pollCustomerHostnameAuthorizationsWithRelay({
        relayUrl,
        intentId,
        chainId: this.requiredConfig("CHAIN_ID"),
        registryAddress: this.requiredConfig("INGRESS_REGISTRY_ADDRESS"),
        sessionId: this.requiredConfig("SESSION_ID"),
        endpointHostname,
        jobSigner,
        requestTimeoutMs: numberConfig(this, "SWITCHBOARD_CUSTOMER_HOSTNAME_POLL_TIMEOUT_MS", this.intentRequestTimeoutMs())
      }, this.fetchImpl);
      const hostnames = customerHostnamePollHostnames(response)
        .map(normalizeHostname)
        .filter((hostname) => !this.managedCertificateContexts.has(hostname));
      if (hostnames.length === 0) {
        return false;
      }
      await this.log("customer-hostname-certificate-requesting", { hostnames }).catch(() => undefined);
      const certificates = await this.requestCertificates(hostnames);
      for (const certificate of certificates) {
        this.addManagedCertificate(certificate);
      }
      this.setRuntimeConfig({
        SWITCHBOARD_CERTIFICATE_HOSTNAMES: this.managedCertificates.map((certificate) => certificate.hostname).join(",")
      });
      await this.log("customer-hostname-certificates-issued", {
        hostnames: certificates.map((certificate) => certificate.hostname),
        certificates: certificates.map((certificate) => ({
          hostname: certificate.hostname,
          issuer: certificate.issuer,
          notAfter: certificate.notAfter
        }))
      }).catch(() => undefined);
      return certificates.length > 0;
    } catch (error) {
      await this.log("customer-hostname-poll-failed", { error: safeError(error) }).catch(() => undefined);
      return false;
    } finally {
      this.customerHostnamePollActive = false;
    }
  }

  private certificateHostnames(): string[] {
    const configured = splitCsv(this.configValue("SWITCHBOARD_CERTIFICATE_HOSTNAMES") ?? "");
    const endpoint = this.configValue("ENDPOINT_HOSTNAME");
    return [...new Set((configured.length > 0 ? configured : endpoint ? [endpoint] : []).map(normalizeHostname).filter(Boolean))];
  }

  private requiredConfig(name: string): string {
    const value = this.configValue(name);
    if (!value) {
      throw new Error(`Missing required Switchboard runtime config: ${name}`);
    }
    return value;
  }

  private intentRequestTimeoutMs(): number {
    return numberConfig(this, "SWITCHBOARD_INTENT_REQUEST_TIMEOUT_MS", DEFAULT_SWITCHBOARD_INTENT_REQUEST_TIMEOUT_MS);
  }
}

export function createSwitchboardRuntime(options: SwitchboardRuntimeOptions = {}): SwitchboardRuntime {
  return new SwitchboardRuntime(options);
}

export const createProofIngressRuntime = createSwitchboardRuntime;

export * from "./network-manifest.js";
export * from "./report-signing.js";
export * from "./service-catalog.js";
export * from "./service-discovery.js";

export function buildSwitchboardChallengeResult(
  config: SwitchboardChallengeConfig,
  request: SwitchboardChallengeRequest
): SwitchboardChallengeResult {
  if (typeof request.nonce !== "string" || request.nonce.length === 0) {
    return {
      statusCode: 400,
      headers: { "cache-control": "no-store" },
      body: { error: "missing_nonce" }
    };
  }

  const timestamp = Math.floor(Date.now() / 1000);
  if (config.onChallenge) {
    void Promise.resolve(
      config.onChallenge({
        nonce: request.nonce,
        timestamp,
        path: request.path,
        userAgent: request.userAgent,
        remoteAddress: request.remoteAddress
      })
    ).catch(() => undefined);
  }

  return {
    statusCode: 200,
    headers: { "cache-control": "no-store" },
    body: {
      sessionId: dynamicString(config.sessionId),
      nonce: request.nonce,
      deploymentId: config.deploymentId,
      jobId: dynamicOptionalString(config.jobId),
      timestamp
    }
  };
}

export const buildProofIngressChallengeResult = buildSwitchboardChallengeResult;

export function registrationDomain(chainId: bigint | number | string, verifyingContract: string) {
  return {
    name: EIP712_DOMAIN_NAME,
    version: EIP712_DOMAIN_VERSION,
    chainId,
    verifyingContract
  };
}

export function registrationDigest(
  chainId: bigint | number | string,
  verifyingContract: string,
  registration: RegistrationPayload
): string {
  return ethers.TypedDataEncoder.hash(
    registrationDomain(chainId, verifyingContract),
    REGISTRATION_TYPES,
    normalizeRegistration(registration)
  );
}

export function endpointHash(hostname: string): string {
  return ethers.keccak256(ethers.toUtf8Bytes(hostname.toLowerCase()));
}

export function normalizeRegistration(registration: RegistrationPayload): RegistrationPayload {
  return {
    sessionId: ethers.hexlify(registration.sessionId),
    jobId: ethers.hexlify(registration.jobId),
    jobSigner: ethers.getAddress(registration.jobSigner),
    operatorId: ethers.hexlify(registration.operatorId),
    processorId: ethers.hexlify(registration.processorId),
    endpointHash: ethers.hexlify(registration.endpointHash),
    nonce: registration.nonce.toString(),
    deadline: registration.deadline.toString()
  };
}

export async function signRegistration(
  wallet: ethers.Wallet,
  chainId: bigint | number | string,
  verifyingContract: string,
  registration: RegistrationPayload
): Promise<string> {
  return wallet.signTypedData(
    registrationDomain(chainId, verifyingContract),
    REGISTRATION_TYPES,
    normalizeRegistration(registration)
  );
}

export function recoverRegistrationSigner(
  chainId: bigint | number | string,
  verifyingContract: string,
  registration: RegistrationPayload,
  signature: string
): string {
  return ethers.verifyTypedData(
    registrationDomain(chainId, verifyingContract),
    REGISTRATION_TYPES,
    normalizeRegistration(registration),
    signature
  );
}

export function certificateRequestDomain(chainId: bigint | number | string, verifyingContract: string) {
  return registrationDomain(chainId, verifyingContract);
}

export function csrPemHash(csrPem: string): string {
  return ethers.keccak256(ethers.toUtf8Bytes(csrPem));
}

export function normalizeCertificateRequest(request: CertificateRequestPayload): CertificateRequestPayload {
  return {
    sessionId: ethers.hexlify(request.sessionId),
    jobSigner: ethers.getAddress(request.jobSigner),
    hostname: request.hostname.trim().toLowerCase(),
    csrHash: ethers.hexlify(request.csrHash),
    nonce: request.nonce.toString(),
    deadline: request.deadline.toString()
  };
}

export function certificateRequestDigest(
  chainId: bigint | number | string,
  verifyingContract: string,
  request: CertificateRequestPayload
): string {
  return ethers.TypedDataEncoder.hash(
    certificateRequestDomain(chainId, verifyingContract),
    CERTIFICATE_REQUEST_TYPES,
    normalizeCertificateRequest(request)
  );
}

export function customerHostnamePollRequestDomain(chainId: bigint | number | string, verifyingContract: string) {
  return {
    name: CUSTOMER_HOSTNAME_POLL_DOMAIN_NAME,
    version: CUSTOMER_HOSTNAME_POLL_DOMAIN_VERSION,
    chainId,
    verifyingContract
  };
}

export function normalizeCustomerHostnamePollRequest(
  request: CustomerHostnamePollRequestPayload
): CustomerHostnamePollRequestPayload {
  return {
    sessionId: ethers.hexlify(request.sessionId),
    jobSigner: ethers.getAddress(request.jobSigner),
    endpointHostname: normalizeHostname(request.endpointHostname),
    nonce: request.nonce.toString(),
    deadline: request.deadline.toString()
  };
}

export function customerHostnamePollRequestDigest(
  chainId: bigint | number | string,
  verifyingContract: string,
  request: CustomerHostnamePollRequestPayload
): string {
  return ethers.TypedDataEncoder.hash(
    customerHostnamePollRequestDomain(chainId, verifyingContract),
    CUSTOMER_HOSTNAME_POLL_REQUEST_TYPES,
    normalizeCustomerHostnamePollRequest(request)
  );
}

export async function signCustomerHostnamePollRequest(
  wallet: ethers.Wallet,
  chainId: bigint | number | string,
  verifyingContract: string,
  request: CustomerHostnamePollRequestPayload
): Promise<string> {
  return wallet.signTypedData(
    customerHostnamePollRequestDomain(chainId, verifyingContract),
    CUSTOMER_HOSTNAME_POLL_REQUEST_TYPES,
    normalizeCustomerHostnamePollRequest(request)
  );
}

export function recoverCustomerHostnamePollRequestSigner(
  chainId: bigint | number | string,
  verifyingContract: string,
  request: CustomerHostnamePollRequestPayload,
  signature: string
): string {
  return ethers.verifyTypedData(
    customerHostnamePollRequestDomain(chainId, verifyingContract),
    CUSTOMER_HOSTNAME_POLL_REQUEST_TYPES,
    normalizeCustomerHostnamePollRequest(request),
    signature
  );
}

export async function signCertificateRequest(
  wallet: ethers.Wallet,
  chainId: bigint | number | string,
  verifyingContract: string,
  request: CertificateRequestPayload
): Promise<string> {
  return wallet.signTypedData(
    certificateRequestDomain(chainId, verifyingContract),
    CERTIFICATE_REQUEST_TYPES,
    normalizeCertificateRequest(request)
  );
}

export function privateKeyJobSigner(privateKey: string): SwitchboardJobSigner {
  const wallet = new ethers.Wallet(privateKey);
  return {
    async getAddress() {
      return wallet.getAddress();
    },
    async signRegistration(input) {
      return signRegistration(wallet, input.chainId, input.registryAddress, input.registration);
    },
    async signCertificateRequest(input) {
      return signCertificateRequest(wallet, input.chainId, input.registryAddress, input.certificateRequest);
    },
    async signCustomerHostnamePollRequest(input) {
      return signCustomerHostnamePollRequest(wallet, input.chainId, input.registryAddress, input.request);
    }
  };
}

export function maybeAcurastJobSigner(std: AcurastRuntimeStd | undefined = (globalThis as { _STD_?: AcurastRuntimeStd })._STD_): SwitchboardJobSigner | undefined {
  if (typeof std?.job?.getPublicKeys !== "function" || typeof std.signers?.secp256k1?.sign !== "function") {
    return undefined;
  }
  return acurastJobSigner(std);
}

export function acurastJobSigner(
  std: AcurastRuntimeStd = requiredAcurastStd()
): SwitchboardJobSigner {
  const getPublicKeys = std.job?.getPublicKeys;
  const sign = std.signers?.secp256k1?.sign;
  if (typeof getPublicKeys !== "function" || typeof sign !== "function") {
    throw new Error("Acurast _STD_.job.getPublicKeys and _STD_.signers.secp256k1.sign are required");
  }

  let addressPromise: Promise<string> | undefined;
  const getAddress = async () => {
    addressPromise ??= Promise.resolve(getPublicKeys.call(std.job)).then((publicKeys) =>
      addressFromSecp256k1PublicKey(secP256k1PublicKey(publicKeys))
    );
    return addressPromise;
  };

  return {
    getAddress,
    async signRegistration(input) {
      const digest = registrationDigest(input.chainId, input.registryAddress, input.registration);
      return signAcurastSecp256k1Digest(sign, digest, await getAddress(), std);
    },
    async signCertificateRequest(input) {
      const digest = certificateRequestDigest(input.chainId, input.registryAddress, input.certificateRequest);
      return signAcurastSecp256k1Digest(sign, digest, await getAddress(), std);
    },
    async signCustomerHostnamePollRequest(input) {
      const digest = customerHostnamePollRequestDigest(input.chainId, input.registryAddress, input.request);
      return signAcurastSecp256k1Digest(sign, digest, await getAddress(), std);
    }
  };
}

export async function buildIngressRegistrationRequest(
  config: SwitchboardRegistrationConfig
): Promise<SwitchboardRegistrationRequest> {
  const jobSigner = config.jobSigner ?? localJobSigner(config.jobSignerPrivateKey);
  const registration = normalizeRegistration({
    sessionId: config.sessionId,
    jobId: config.jobId,
    jobSigner: await jobSigner.getAddress(),
    operatorId: config.operatorId,
    processorId: config.processorId,
    endpointHash: resolveEndpointHash(config),
    nonce: config.nonce ?? "1",
    deadline: config.deadline ?? Math.floor(Date.now() / 1000) + 600
  });
  const signature = await jobSigner.signRegistration({
    chainId: config.chainId,
    registryAddress: config.registryAddress,
    registration
  });
  return { registration, signature };
}

export async function registerIngressWithRelay(
  config: SwitchboardRegistrationConfig,
  fetchImpl: typeof fetch = fetch
): Promise<SwitchboardRegistrationResult> {
  const request = await buildIngressRegistrationRequest(config);
  const response = await fetchImpl(new URL("/v1/ingress-registrations", config.relayUrl), {
    method: "POST",
    headers: { "content-type": "application/json" },
    signal: AbortSignal.timeout(config.requestTimeoutMs ?? 120_000),
    body: JSON.stringify(request)
  });
  const relayResponse = await response.json();
  if (!response.ok) {
    throw new Error(`Relay registration failed: ${JSON.stringify(relayResponse)}`);
  }
  return { ...request, relayResponse };
}

export async function createSwitchboardCertificateSigningRequest(
  hostname: string
): Promise<SwitchboardCertificateSigningRequest> {
  const normalizedHostname = normalizeHostname(hostname);
  const [privateKey, csr] = await acme.crypto.createCsr({
    commonName: normalizedHostname,
    altNames: [normalizedHostname]
  });
  return {
    privateKeyPem: privateKey.toString("utf8"),
    csrPem: csr.toString("utf8")
  };
}

export const createProofIngressCertificateSigningRequest = createSwitchboardCertificateSigningRequest;

export async function buildIngressCertificateRequest(
  config: SwitchboardCertificateConfig
): Promise<SwitchboardCertificateRelayRequest & { privateKeyPem?: string }> {
  const jobSigner = config.jobSigner ?? localJobSigner(config.jobSignerPrivateKey);
  const csr =
    config.csrPem == null
      ? await createSwitchboardCertificateSigningRequest(config.hostname)
      : { csrPem: config.csrPem, privateKeyPem: config.privateKeyPem };
  const certificateRequest: CertificateRequestPayload = {
    sessionId: ethers.hexlify(config.sessionId),
    jobSigner: await jobSigner.getAddress(),
    hostname: normalizeHostname(config.hostname),
    csrHash: csrPemHash(csr.csrPem),
    nonce: config.nonce ?? Date.now(),
    deadline: config.deadline ?? Math.floor(Date.now() / 1000) + 600
  };
  const signature = await jobSigner.signCertificateRequest({
    chainId: config.chainId,
    registryAddress: config.registryAddress,
    certificateRequest
  });
  return {
    certificateRequest,
    csrPem: csr.csrPem,
    signature,
    privateKeyPem: csr.privateKeyPem
  };
}

export async function requestCertificateWithRelay(
  config: SwitchboardCertificateConfig,
  fetchImpl: typeof fetch = fetch
): Promise<SwitchboardCertificateResult> {
  const request = await buildIngressCertificateRequest(config);
  const response = await fetchImpl(new URL("/v1/certificates", config.relayUrl), {
    method: "POST",
    headers: { "content-type": "application/json" },
    signal: AbortSignal.timeout(config.requestTimeoutMs ?? 120_000),
    body: JSON.stringify({
      certificateRequest: request.certificateRequest,
      csrPem: request.csrPem,
      signature: request.signature
    })
  });
  const relayResponse = await responseJsonOrText(response) as SwitchboardCertificateResult["relayResponse"];
  if (!response.ok) {
    throw new SwitchboardCertificateError(
      `Relay certificate request failed for ${normalizeHostname(config.hostname)}: ${response.status} ${JSON.stringify(relayResponse)}`,
      {
        stage: certificateFailureStageForRelayResponse(response.status, relayResponse),
        hostname: normalizeHostname(config.hostname),
        status: response.status,
        relayResponse
      }
    );
  }
  return { ...request, relayResponse };
}

export async function buildCustomerHostnamePollRequest(
  config: SwitchboardCustomerHostnamePollConfig
): Promise<SwitchboardCustomerHostnamePollRelayRequest> {
  const jobSigner = config.jobSigner ?? localJobSigner(config.jobSignerPrivateKey);
  if (typeof jobSigner.signCustomerHostnamePollRequest !== "function") {
    throw new Error("Switchboard job signer does not support customer hostname polling signatures");
  }
  const request: CustomerHostnamePollRequestPayload = normalizeCustomerHostnamePollRequest({
    sessionId: config.sessionId,
    jobSigner: await jobSigner.getAddress(),
    endpointHostname: config.endpointHostname,
    nonce: config.nonce ?? Date.now(),
    deadline: config.deadline ?? Math.floor(Date.now() / 1000) + 600
  });
  const signature = await jobSigner.signCustomerHostnamePollRequest({
    chainId: config.chainId,
    registryAddress: config.registryAddress,
    request
  });
  return { request, signature };
}

export async function pollCustomerHostnameAuthorizationsWithRelay(
  config: SwitchboardCustomerHostnamePollConfig,
  fetchImpl: typeof fetch = fetch
): Promise<SwitchboardCustomerHostnamePollResponse> {
  const request = await buildCustomerHostnamePollRequest(config);
  const response = await fetchImpl(
    new URL(`/v1/deployment-intents/${encodeURIComponent(config.intentId)}/customer-hostname-authorizations`, config.relayUrl),
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      signal: AbortSignal.timeout(config.requestTimeoutMs ?? 60_000),
      body: JSON.stringify(request)
    }
  );
  const relayResponse = await responseJsonOrText(response) as SwitchboardCustomerHostnamePollResponse;
  if (!response.ok) {
    throw new Error(`Relay customer hostname authorization poll failed: ${response.status} ${JSON.stringify(relayResponse)}`);
  }
  return relayResponse;
}

export function createEncryptedSwitchboardLogger(
  config: SwitchboardRemoteLoggerConfig
): (event: string, details?: Record<string, unknown>) => Promise<void> {
  if (!config.logUrl) {
    return async () => undefined;
  }
  if (!config.encryptionKey) {
    return async (event) => {
      config.onError?.(new Error("Encrypted Switchboard logging requires SWITCHBOARD_LOG_ENCRYPTION_KEY"), event);
    };
  }

  const fetchImpl = config.fetchImpl ?? fetch;
  return async (event: string, details: Record<string, unknown> = {}) => {
    try {
      const record: SwitchboardLogRecord = {
        ...config.baseRecord?.(),
        timestamp: new Date().toISOString(),
        event,
        context: config.context,
        details
      };
      const encrypted = encryptProofLogRecord(config.encryptionKey!, record);
      const response = await fetchImpl(config.logUrl!, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(config.writeToken ? { authorization: `Bearer ${config.writeToken}` } : {})
        },
        signal: AbortSignal.timeout(config.timeoutMs ?? 5_000),
        body: JSON.stringify({ encrypted })
      });
      if (!response.ok) {
        throw new Error(`Encrypted Switchboard log failed: ${response.status} ${await response.text()}`);
      }
    } catch (error) {
      config.onError?.(error, event);
    }
  };
}

export const createEncryptedProofIngressLogger = createEncryptedSwitchboardLogger;

export function generateProofLogEncryptionKey(): string {
  return base64UrlEncode(randomBytes(32));
}

export function encryptProofLogRecord(key: string, value: unknown): ProofLogEncryptedRecord {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", decodeProofLogKey(key), iv);
  const plaintext = Buffer.from(JSON.stringify(value), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    v: 1,
    alg: "A256GCM",
    iv: base64UrlEncode(iv),
    ciphertext: base64UrlEncode(ciphertext),
    tag: base64UrlEncode(tag)
  };
}

export function decryptProofLogRecord<T = unknown>(key: string, encrypted: ProofLogEncryptedRecord): T {
  if (encrypted.v !== 1 || encrypted.alg !== "A256GCM") {
    throw new Error(`Unsupported encrypted log record format: v=${encrypted.v} alg=${encrypted.alg}`);
  }
  const decipher = createDecipheriv("aes-256-gcm", decodeProofLogKey(key), base64UrlDecode(encrypted.iv));
  decipher.setAuthTag(base64UrlDecode(encrypted.tag));
  const plaintext = Buffer.concat([
    decipher.update(base64UrlDecode(encrypted.ciphertext)),
    decipher.final()
  ]).toString("utf8");
  return JSON.parse(plaintext) as T;
}

export function tlsOptionsForManagedCertificates(certificates: SwitchboardManagedCertificate[]): SwitchboardTlsOptions | undefined {
  if (certificates.length === 0) {
    return undefined;
  }
  const contexts = new Map(
    certificates.map((certificate) => [
      normalizeHostname(certificate.hostname),
      tls.createSecureContext({
        cert: certificate.cert,
        key: certificate.key
      })
    ])
  );
  const defaultCertificate = certificates[0]!;
  const defaultContext = contexts.get(normalizeHostname(defaultCertificate.hostname));
  return {
    cert: defaultCertificate.cert,
    key: defaultCertificate.key,
    SNICallback: (servername, callback) => {
      const context = contexts.get(normalizeHostname(servername)) ?? defaultContext;
      if (!context) {
        callback(new Error("No TLS context available"));
        return;
      }
      callback(null, context);
    }
  };
}

export function readSwitchboardConfig(
  env: NodeJS.ProcessEnv = process.env,
  std: AcurastRuntimeStd | undefined = (globalThis as { _STD_?: AcurastRuntimeStd })._STD_
): Record<string, string> {
  const raw = envValue("SWITCHBOARD_CONFIG", env, std) ?? envValue("PROOF_INGRESS_CONFIG", env, std);
  if (!raw) {
    return {};
  }
  const json = raw.trim().startsWith("{") ? raw : Buffer.from(raw, "base64").toString("utf8");
  const parsed = JSON.parse(json) as Record<string, unknown>;
  return Object.fromEntries(
    Object.entries(parsed)
      .filter(([, value]) => value !== undefined && value !== null)
      .map(([key, value]) => [key, String(value)])
  );
}

export function acurastDeploymentId(std: AcurastRuntimeStd | undefined = (globalThis as { _STD_?: AcurastRuntimeStd })._STD_): string | undefined {
  const getId = std?.job?.getId;
  if (typeof getId !== "function") {
    return undefined;
  }
  const id = getId();
  return typeof id === "string" ? id : JSON.stringify(id);
}

export function acurastDeploymentSequence(value: string | undefined): string | undefined {
  if (!value) {
    return undefined;
  }
  if (/^[0-9]+$/.test(value)) {
    return value;
  }
  try {
    const parsed = JSON.parse(value) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      const id = (parsed as { id?: unknown }).id;
      if (typeof id === "number" && Number.isInteger(id) && id >= 0) {
        return String(id);
      }
      if (typeof id === "string" && /^[0-9]+$/.test(id)) {
        return id;
      }
    }
    if (Array.isArray(parsed) && parsed.length >= 2) {
      const id = parsed[1];
      if (typeof id === "number" && Number.isInteger(id) && id >= 0) {
        return String(id);
      }
      if (typeof id === "string" && /^[0-9]+$/.test(id)) {
        return id;
      }
    }
  } catch {
    return undefined;
  }
  return undefined;
}

export function publicNetworkAddresses(): string[] {
  try {
    return [
      ...new Set(
        Object.values(networkInterfaces())
          .flatMap((values) => values ?? [])
          .filter((item) => item.internal === false && String(item.family) === "IPv4")
          .map((item) => item.address)
          .filter((value): value is string => typeof value === "string" && value.length > 0)
      )
    ];
  } catch {
    return [];
  }
}

export function allowAcurastHostname(rawUrl: string, std: AcurastRuntimeStd | undefined = (globalThis as { _STD_?: AcurastRuntimeStd })._STD_): void {
  let hostname: string;
  try {
    hostname = new URL(rawUrl).hostname;
  } catch {
    return;
  }
  const addAllowedHostnames = std?.net?.addAllowedHostnames;
  if (typeof addAllowedHostnames !== "function") {
    return;
  }
  try {
    void Promise.resolve(addAllowedHostnames([hostname])).catch(() => undefined);
  } catch {
    return;
  }
}

function localJobSigner(privateKey: string | undefined): SwitchboardJobSigner {
  if (!privateKey) {
    const acurastSigner = maybeAcurastJobSigner();
    if (acurastSigner) {
      return acurastSigner;
    }
    throw new Error("JOB_SIGNER_PRIVATE_KEY is required outside the Acurast runtime.");
  }
  return privateKeyJobSigner(privateKey);
}

function requiredAcurastStd(): AcurastRuntimeStd {
  const std = (globalThis as { _STD_?: AcurastRuntimeStd })._STD_;
  if (!std) {
    throw new Error("Acurast _STD_ runtime object is not available");
  }
  return std;
}

async function signAcurastSecp256k1Digest(
  sign: (payload: string) => string | Promise<string>,
  digest: string,
  expectedAddress: string,
  std: AcurastRuntimeStd
): Promise<string> {
  const rawSignature = await Promise.resolve(sign.call(std.signers?.secp256k1, digest));
  return normalizeAcurastSecp256k1Signature(rawSignature, digest, expectedAddress);
}

export function normalizeAcurastSecp256k1Signature(
  rawSignature: string,
  digest: string,
  expectedAddress: string
): string {
  const parsed = parseAcurastSecp256k1Signature(rawSignature);
  const expected = ethers.getAddress(expectedAddress);
  const vCandidates = parsed.v == null ? [27, 28] : [normalizeV(parsed.v)];

  for (const v of vCandidates) {
    const normalized = normalizeSignatureS(parsed.r, parsed.s, v);
    if (normalized == null) {
      continue;
    }
    const signature = serializeSignature(normalized.r, normalized.s, normalized.v);
    try {
      if (ethers.getAddress(ethers.recoverAddress(digest, signature)) === expected) {
        return signature;
      }
    } catch {
      continue;
    }
  }

  throw new Error("Acurast secp256k1 signature could not be recovered to the job public key");
}

function secP256k1PublicKey(publicKeys: unknown): string {
  const parsed = typeof publicKeys === "string" ? parsePublicKeys(publicKeys) : publicKeys;
  const key = (parsed as { secp256k1?: unknown } | null | undefined)?.secp256k1;
  if (typeof key !== "string" || key.length === 0) {
    throw new Error("Acurast job public keys did not include secp256k1");
  }
  return key;
}

function parsePublicKeys(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    return { secp256k1: value };
  }
}

function addressFromSecp256k1PublicKey(publicKey: string): string {
  return ethers.computeAddress(hex(publicKey));
}

function parseAcurastSecp256k1Signature(rawSignature: string): { r: bigint; s: bigint; v?: number } {
  const bytes = ethers.getBytes(hex(rawSignature));
  if (bytes.length === 64 || bytes.length === 65) {
    return {
      r: bytesToBigInt(bytes.slice(0, 32)),
      s: bytesToBigInt(bytes.slice(32, 64)),
      v: bytes.length === 65 ? bytes[64] : undefined
    };
  }
  throw new Error(`Unsupported Acurast secp256k1 signature length: ${bytes.length} bytes`);
}

const SECP256K1_N = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
const SECP256K1_HALF_N = SECP256K1_N / 2n;

function normalizeSignatureS(r: bigint, s: bigint, v: number): { r: bigint; s: bigint; v: number } | null {
  if (v !== 27 && v !== 28) {
    return null;
  }
  if (s > SECP256K1_HALF_N) {
    return { r, s: SECP256K1_N - s, v: v === 27 ? 28 : 27 };
  }
  return { r, s, v };
}

function normalizeV(v: number): number {
  return v < 27 ? v + 27 : v;
}

function serializeSignature(r: bigint, s: bigint, v: number): string {
  return `${ethers.toBeHex(r, 32)}${ethers.toBeHex(s, 32).slice(2)}${ethers.toBeHex(v, 1).slice(2)}`;
}

function resolveEndpointHash(config: SwitchboardRegistrationConfig): string {
  if (config.endpointHash) {
    return config.endpointHash;
  }
  if (config.endpointHostname) {
    return endpointHash(config.endpointHostname);
  }
  throw new Error("endpointHostname or endpointHash is required");
}

interface AcurastProcessorIdentity {
  processorId?: string;
  processor?: string;
  address?: string;
  raw?: unknown;
  source: "_STD_.job.getProcessorId" | "_STD_.device.getAddress";
}

function acurastProcessorIdentity(std?: AcurastRuntimeStd): AcurastProcessorIdentity {
  const job = std?.job;
  const jobProcessor = job?.getProcessorId;
  if (typeof jobProcessor === "function") {
    const identity = normalizeAcurastProcessorIdentity(jobProcessor.call(job), "_STD_.job.getProcessorId");
    if (identity) return identity;
  }
  const device = std?.device;
  const deviceAddress = device?.getAddress;
  if (typeof deviceAddress === "function") {
    const identity = normalizeAcurastProcessorIdentity(deviceAddress.call(device), "_STD_.device.getAddress");
    if (identity) return identity;
  }
  throw new Error("Switchboard group intent requires Acurast processor identity from _STD_.job.getProcessorId() or _STD_.device.getAddress()");
}

function normalizeAcurastProcessorIdentity(
  raw: unknown,
  source: AcurastProcessorIdentity["source"]
): AcurastProcessorIdentity | undefined {
  if (typeof raw === "string" && raw.length > 0) {
    return hex32String(raw)
      ? { processorId: raw, raw, source }
      : { processor: raw, address: raw, raw, source };
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return undefined;
  }
  const record = raw as Record<string, unknown>;
  const processorId = stringRecordField(record, "processorId") ?? stringRecordField(record, "id");
  const processor = stringRecordField(record, "processor") ?? stringRecordField(record, "address") ?? stringRecordField(record, "deviceAddress");
  const address = stringRecordField(record, "address") ?? stringRecordField(record, "deviceAddress") ?? processor;
  if (processorId || processor || address) {
    return {
      processorId: processorId && hex32String(processorId) ? processorId : undefined,
      processor,
      address,
      raw,
      source
    };
  }
  return undefined;
}

function hex32String(value: string): boolean {
  return /^0x[0-9a-fA-F]{64}$/.test(value);
}

function configNameCandidates(name: string): string[] {
  if (name.startsWith("SWITCHBOARD_")) {
    return [name, `PROOF_INGRESS_${name.slice("SWITCHBOARD_".length)}`];
  }
  return [name];
}

function envValue(name: string, env: NodeJS.ProcessEnv, std?: AcurastRuntimeStd): string | undefined {
  const processValue = env[name];
  if (processValue) {
    return processValue;
  }
  const acurastEnv = std?.env?.[name];
  if (typeof acurastEnv === "string" && acurastEnv.length > 0) {
    return acurastEnv;
  }
  const environment = (globalThis as { environment?: (name: string) => unknown }).environment;
  if (typeof environment === "function") {
    const value = environment(name);
    return typeof value === "string" && value.length > 0 ? value : undefined;
  }
  return undefined;
}

function asSwitchboardCertificateError(
  error: unknown,
  fallback: Pick<SwitchboardCertificateErrorOptions, "stage" | "hostname">
): SwitchboardCertificateError {
  if (error instanceof SwitchboardCertificateError) {
    return error;
  }
  const message = error instanceof Error ? error.message : String(error);
  return new SwitchboardCertificateError(message, {
    ...fallback,
    cause: error
  });
}

function switchboardCertificateErrorDetails(error: SwitchboardCertificateError): Record<string, unknown> {
  const details: Record<string, unknown> = {
    stage: error.stage,
    error: safeCertificateError(error)
  };
  if (error.hostname) {
    details.hostname = error.hostname;
  }
  if (error.status !== undefined) {
    details.status = error.status;
  }
  const relayError = stringRecordField(error.relayResponse, "error");
  if (relayError) {
    details.relayError = relayError;
  }
  if (error.relayResponse !== undefined) {
    details.relayResponse = sanitizeRelayResponse(error.relayResponse);
  }
  return details;
}

function safeCertificateError(error: SwitchboardCertificateError): Record<string, unknown> {
  return {
    name: error.name,
    message: error.message,
    stage: error.stage,
    hostname: error.hostname,
    status: error.status
  };
}

function certificateFailureStageForRelayResponse(
  status: number,
  relayResponse: SwitchboardCertificateResult["relayResponse"]
): SwitchboardCertificateFailureStage {
  const relayError = stringRecordField(relayResponse, "error");
  if (relayError === "certificate_hostname_lock_unavailable" || status === 423) {
    return "certificate_lock";
  }
  if (relayError === "certificate_hostname_not_authorized" || relayError === "certificate_hostname_byo_tls") {
    return "certificate_authorization";
  }
  if (relayError === "certificate_issuance_failed") {
    return "acme_issuance";
  }
  if (status === 400 && (relayError === "invalid_hostname" || relayError === "invalid_request")) {
    return "hostname_config";
  }
  return "relay_response";
}

function certificateRetryAfterMs(error: SwitchboardCertificateError): number | undefined {
  const relayError = stringRecordField(error.relayResponse, "error");
  if (relayError !== "certificate_hostname_lock_unavailable") {
    return undefined;
  }
  const retryAfterMs = numberRecordField(error.relayResponse, "retryAfterMs");
  if (retryAfterMs !== undefined && retryAfterMs >= 0) {
    return retryAfterMs;
  }
  const retryAfterSeconds = numberRecordField(error.relayResponse, "retryAfterSeconds");
  return retryAfterSeconds !== undefined && retryAfterSeconds >= 0 ? retryAfterSeconds * 1000 : undefined;
}

async function responseJsonOrText(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) {
    return {};
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return { body: text };
  }
}

function numberConfig(runtime: SwitchboardRuntime, name: string, fallback: number): number {
  const raw = runtime.configValue(name);
  if (!raw) {
    return fallback;
  }
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

function requiredRuntimeConfig(value: string | undefined, name: string): string {
  if (!value) {
    throw new Error(`Switchboard runtime config missing ${name}`);
  }
  return value;
}

function requiredRegistrationEnv(): string[] {
  return [
    "RELAY_URL",
    "CHAIN_ID",
    "INGRESS_REGISTRY_ADDRESS",
    "SESSION_ID",
    "JOB_ID",
    "OPERATOR_ID",
    "PROCESSOR_ID",
    "ENDPOINT_HOSTNAME"
  ];
}

function gatewayIdFromRuntimeResponse(response: SwitchboardRuntimeConfigResponse): string | undefined {
  return (
    response.config?.gatewayId ??
    stringRecordField((response.intent as Record<string, unknown> | undefined)?.allocation, "gatewayId") ??
    stringRecordField(response.intent, "gatewayId")
  );
}

function stringRecordField(record: unknown, name: string): string | undefined {
  if (!record || typeof record !== "object") {
    return undefined;
  }
  const value = (record as Record<string, unknown>)[name];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function numberRecordField(record: unknown, name: string): number | undefined {
  if (!record || typeof record !== "object") {
    return undefined;
  }
  const value = (record as Record<string, unknown>)[name];
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === "string" && value.length > 0) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : undefined;
  }
  return undefined;
}

function dynamicString(value: string | (() => string)): string {
  return typeof value === "function" ? value() : value;
}

function dynamicOptionalString(value: string | (() => string | undefined) | undefined): string | undefined {
  return typeof value === "function" ? value() : value;
}

function splitCsv(value: string): string[] {
  return value.split(",").map((item) => item.trim()).filter(Boolean);
}

function normalizeHostname(hostname: string): string {
  return hostname.trim().replace(/\.$/, "").toLowerCase();
}

function customerHostnamePollHostnames(response: SwitchboardCustomerHostnamePollResponse): string[] {
  const direct = Array.isArray(response.hostnames) ? response.hostnames : [];
  const fromAuthorizations = Array.isArray(response.authorizations)
    ? response.authorizations.map((authorization) => authorization.customerHostname)
    : [];
  return [...new Set([...direct, ...fromAuthorizations].filter((hostname): hostname is string =>
    typeof hostname === "string" && hostname.length > 0
  ))];
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function safeError(error: unknown): Record<string, unknown> {
  if (error instanceof Error) {
    const details: Record<string, unknown> = { name: error.name, message: error.message, stack: error.stack };
    if (error instanceof SwitchboardCertificateError) {
      details.stage = error.stage;
      details.hostname = error.hostname;
      details.status = error.status;
    }
    return details;
  }
  return { message: String(error) };
}

function safeUrlHost(value: string): string | undefined {
  try {
    return new URL(value).host;
  } catch {
    return undefined;
  }
}

function sanitizeRelayResponse(value: unknown): unknown {
  if (!value || typeof value !== "object") {
    return value;
  }
  const record = { ...(value as Record<string, unknown>) };
  for (const key of ["authorityToken", "token", "leaseToken"]) {
    if (key in record) {
      record[key] = "[redacted]";
    }
  }
  return record;
}

function runtimeSummary(std?: AcurastRuntimeStd): Record<string, unknown> {
  return {
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch,
    pid: process.pid,
    uptimeSeconds: Math.round(process.uptime()),
    hasStd: Boolean(std),
    hasStdEnv: Boolean(std?.env),
    hasStdJobGetId: typeof std?.job?.getId === "function",
    hasStdJobGetProcessorId: typeof std?.job?.getProcessorId === "function",
    hasStdJobGetPublicKeys: typeof std?.job?.getPublicKeys === "function",
    hasStdDeviceGetAddress: typeof std?.device?.getAddress === "function",
    hasStdSignersSecp256k1: typeof std?.signers?.secp256k1?.sign === "function",
    hasStdNetAddAllowedHostnames: typeof std?.net?.addAllowedHostnames === "function"
  };
}

function decodeProofLogKey(key: string): Buffer {
  const decoded = base64UrlDecode(key);
  if (decoded.length !== 32) {
    throw new Error("Switchboard log encryption key must decode to 32 bytes");
  }
  return decoded;
}

function base64UrlEncode(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function base64UrlDecode(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("Expected base64url value");
  }
  return Buffer.from(value, "base64url");
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  return BigInt(ethers.hexlify(bytes));
}

function hex(value: string): string {
  return value.startsWith("0x") ? value : `0x${value}`;
}
