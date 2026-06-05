# Switchboard SDK

Runtime and workflow helpers for Acurast jobs deployed through Switchboard.

This package is public for GitHub installs during the private beta. It is not
published on npmjs.com yet.

## Install

```sh
npm install github:proof-computer/switchboard-sdk#v0.1.5
```

Framework apps usually install one adapter instead:

```sh
npm install github:proof-computer/switchboard-express#v0.1.4 express
npm install github:proof-computer/switchboard-fastify#v0.1.5 fastify
```

Use `#main` only when intentionally testing unreleased changes. npmjs.com
publishing is prepared but not active yet.

## Runtime API

```ts
import { createSwitchboardRuntime } from "@proofcomputer/switchboard-sdk";

const runtime = createSwitchboardRuntime();

await runtime.prepare();
```

Do not put developer-machine secrets in the app bundle.

## Deploy Workflow API

The deploy lifecycle is also available as resumable SDK primitives:

```ts
import { SwitchboardControlPlaneClient } from "@proofcomputer/switchboard-sdk/control-plane";
import { SwitchboardDeployWorkflow } from "@proofcomputer/switchboard-sdk/workflows";
```

Use `control-plane` for typed relay calls, `funding` for quote resume/action
planning, and `workflows` for the deploy state machine. The workflow core never
reads seed environment variables or prompts. Callers provide adapters for
Acurast deployment, Hub funding/signing, confirmation, and persistence.

The `switchboard` CLI remains the interactive shell for local signing,
plaintext inputs, and progress output.
