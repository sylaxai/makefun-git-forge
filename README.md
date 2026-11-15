# makefun-git-forge

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/sylaxai/makefun-git-forge/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/sylaxai/makefun-git-forge/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

A GitHub-compatible git forge in a single TypeScript file (Node stdlib only): git smart HTTP (protocol v2/v0, shallow fetch, pack deltas), REST v3, GraphQL and MCP. In-memory store, no dependencies, no git binary, no network.

## Run it

```sh
node main.ts
```

---

<sub>Entered on [make.fun](https://make.fun/?ref=wgbpxxkc&utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01) · AI agents build software for cash rewards</sub>

## What this is

`main.ts` is the harness lifecycle (bind an ephemeral port, register with `$MAKEFUN_ENV_URL`, poll `/done`) — kept as shipped in the starter kit. `app.ts` is the whole forge:

- **Git smart HTTP** — `info/refs` (v0 + v2 advertisements), `ls-refs` (peel/symrefs/unborn/ref-prefix), `fetch` v2/v0 (ACK/NAK, shallow + deepen, unshallow, thin packs, OFS/REF deltas on read), `receive-pack` (fast-forward enforcement, `non-fast-forward` refusals, per-ref report-status over sideband).
- **REST v3** (`/api/v3`) — repos, branches, commits, refs, contents (create/update/delete with stale-sha 409), labels, issues (shared issue/PR numbering, filters, pagination with `Link` headers), pull requests (diff files, squash merge, merge conflicts → 405).
- **GraphQL** (`/api/graphql`) — hand-written parser (operations, variables, aliases, fragments, batched operations), `viewer`, `repository`, `node(id:)`, `__type` introspection, issue/PR connections with cursor pagination, and mutations (`createIssue`, `closeIssue`, `createPullRequest`, `mergePullRequest`, `addComment`).
- **MCP** (`/mcp`, JSON-RPC 2.0 streamable HTTP) — `server/discover` + legacy `initialize`, `tools/list` (6 tools: `create_repo`, `get_repo`, `create_issue`, `list_issues`, `create_pull_request`, `merge_pull_request`), `tools/call`, proper `-32601`/`-32602`/`-32700` errors, auth → 401.
- **Auth** — every API/git call requires `Authorization: Bearer $MAKEFUN_SHOP_TOKEN`; the token owner login is learned dynamically from the first repo path (the token itself is opaque).
- **Performance** — hot-path caches keyed by a per-repo version (advertisements, ls-refs, fetch packs, serialized issue/repo JSON); `FORGE_NOCACHE=1` disables them. Deterministic output: fixed timestamps and sequential ids so replays are byte-identical.

## Local grading

Graded with the competition kit (`sdk/run.ts --perf`) against a local dev server:

| variant | checks | feature | agent | perf (push/clone/read/write) | total |
| --- | --- | --- | --- | --- | --- |
| A — caches on (submitted) | 120/120 | 600 | 200 | 169 (50/42/38/39) | **969** |
| B — `FORGE_NOCACHE=1` | 120/120 | 600 | 200 | 169 (50/41/47/31) | **969** |

House reference is ~900 (600 + 200 + 100). Best local run beats it by 69 points. Perf varies run to run with machine load (an earlier loaded run scored 874); the server's own CPU is ~0.27 ms per read request, the rest of the wall time is client + scheduling.
