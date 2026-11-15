// Entry point: run the forge server and follow the trial env's lifecycle.
// The env (reached through MAKEFUN_ENV_URL) owns port 8080, so this process
// binds an ephemeral port instead, tells the env about it, and then waits
// until the env reports the trial is done. No third-party packages: the only
// import is the forge itself.

import { createApp } from "./app.ts";

const envOrigin = (process.env.MAKEFUN_ENV_URL ?? "").replace(/\/+$/, "");
if (envOrigin === "") {
  process.stderr.write("[entry] MAKEFUN_ENV_URL is not set, nothing to register with\n");
  process.exit(1);
}

// One request may take at most 30 seconds; a failed attempt waits a little
// longer each time (250 ms, doubling, at most 2 s) before it is retried.
const REQUEST_BUDGET_MS = 30_000;
const FIRST_WAIT_MS = 250;
const LONGEST_WAIT_MS = 2_000;

const pause = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

function waitAfter(failures: number): number {
  return Math.min(LONGEST_WAIT_MS, FIRST_WAIT_MS * 2 ** Math.min(failures, 8));
}

// Tell the env which port the forge listens on. 200 means accepted; 409 means
// another entry registered first, which is fine — this process just waits
// like any other. 400/405 mean the request itself is wrong and are fatal;
// anything else (or a network error) is retried, the env may still be coming up.
async function announce(port: number): Promise<void> {
  for (let failures = 0; ; failures += 1) {
    try {
      const res = await fetch(`${envOrigin}/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(REQUEST_BUDGET_MS),
      });
      if (res.status === 200 || res.status === 409) return;
      if (res.status === 400 || res.status === 405) {
        throw new Error(`register refused: HTTP ${res.status} ${await res.text()}`);
      }
    } catch (err) {
      if (err instanceof Error && err.message.startsWith("register refused: ")) throw err;
    }
    await pause(waitAfter(failures));
  }
}

// Ask the env whether the trial is over, until it says it is. A slow or
// failed poll is just retried; this never returns early.
async function waitForDone(): Promise<void> {
  for (let failures = 0; ; failures += 1) {
    try {
      const res = await fetch(`${envOrigin}/done`, {
        signal: AbortSignal.timeout(REQUEST_BUDGET_MS),
      });
      if (res.ok) {
        const body = (await res.json()) as { done?: unknown };
        if (body.done === true) return;
      }
    } catch {
      // Not answering yet (or the request timed out): keep polling.
    }
    await pause(waitAfter(failures));
  }
}

async function run(): Promise<void> {
  const server = createApp();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("the server did not bind an ephemeral TCP port");
  }
  process.stdout.write("[entry] listening on port " + address.port + "\n");

  await announce(address.port);
  process.stdout.write("[entry] registered; waiting for the env to say done\n");

  await waitForDone();
  server.close();
  process.stdout.write("[entry] done\n");
}

try {
  await run();
  process.exit(0);
} catch (err) {
  process.stderr.write("[entry] " + (err instanceof Error ? err.message : String(err)) + "\n");
  process.exit(1);
}
