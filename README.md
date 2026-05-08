# Switchboard SDK

Runtime helpers for Acurast jobs deployed through Switchboard.

This package is public for GitHub installs during the private beta. It is not
published on npmjs.com yet.

## Install

```sh
npm install github:proof-computer/switchboard-sdk#v0.1.0
```

Framework apps usually install one adapter instead:

```sh
npm install github:proof-computer/switchboard-express#v0.1.0 express
npm install github:proof-computer/switchboard-fastify#v0.1.0 fastify
```

Use `#main` only when intentionally testing unreleased changes. npmjs.com
publishing is prepared but not active yet.

## Runtime

```ts
import { createSwitchboardRuntime } from "@proofcomputer/switchboard-sdk";

const runtime = createSwitchboardRuntime();

await runtime.prepare();
```

Do not put developer-machine secrets in the app bundle. Deploy, funding, DNS,
and recovery belong to the `switchboard` CLI.
