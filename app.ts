// Forge: a standalone GitHub-compatible git forge in one process, stdlib only.
//
// Serves git smart HTTP (upload-pack v2 + v0, receive-pack v0), the REST v3 API,
// GraphQL v4 and MCP (2026-07-28 discover era + legacy initialize handshake) from
// one in-memory store. No UI, no outside service, no git binary.
//
// Determinism: every id is a counter, every timestamp the suite can see is fixed, so
// two runs on the same instance leave the same state.
//
// Performance: the hot paths (issue reads, pushes, shallow clones) are served from
// per-repo caches that invalidate on a version bump; pack bytes for a repeated fetch
// are built once.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { inflateSync, deflateSync } from 'node:zlib';

// ---------------------------------------------------------------------------
// constants & tiny utils
// ---------------------------------------------------------------------------

const JSON_TYPE = 'application/json; charset=utf-8';
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const BEARER = `Bearer ${TOKEN}`;
const NOCACHE = process.env.FORGE_NOCACHE === '1';
const FIXED_ISO = '2025-01-01T00:00:00Z';
const FIXED_EPOCH = 1700000000;
const FORGE_IDENTITY = 'Forge <forge@localhost>';
const ZERO_OID = '0'.repeat(40);
const EMPTY_BODY = Buffer.alloc(0);
const HEX40 = /^[0-9a-f]{40}$/;

function sha1(data: Buffer | string): string {
  return createHash('sha1').update(data).digest('hex');
}

function hashObject(type: string, data: Buffer): string {
  return createHash('sha1').update(`${type} ${data.length}\0`, 'utf8').update(data).digest('hex');
}

function b64encode(buf: Buffer): string {
  return buf.toString('base64');
}

function b64decode(text: string): Buffer {
  return Buffer.from(text.replace(/[\r\n\t ]+/g, ''), 'base64');
}

function isOid(s: string): boolean {
  return HEX40.test(s);
}

/** Non-empty X-GitHub-Request-Id values, cheap and unique per request. */
let reqCounter = 0;
function nextRequestId(): string {
  reqCounter += 1;
  return `forge-${reqCounter.toString(36)}`;
}

function esc(s: string): string {
  return JSON.stringify(s);
}

// ---------------------------------------------------------------------------
// pkt-line framing
// ---------------------------------------------------------------------------

function pktLine(payload: Buffer | string): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = body.length + 4;
  const out = Buffer.allocUnsafe(len);
  out.write(len.toString(16).padStart(4, '0'), 0, 4, 'ascii');
  body.copy(out, 4);
  return out;
}

/** One sideband band-1 packet (4-byte length + band byte + payload) in a single allocation. */
function band1PktLine(payload: Buffer): Buffer {
  const len = payload.length + 5;
  const out = Buffer.allocUnsafe(len);
  out.write(len.toString(16).padStart(4, '0'), 0, 4, 'ascii');
  out[4] = 1;
  payload.copy(out, 5);
  return out;
}

const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

interface Pkt {
  kind: 'data' | 'flush' | 'delim';
  payload: Buffer;
}

/** Parse a whole buffer of pkt-lines. Stops at the first malformed line (returns what it got). */
function parsePktLines(buf: Buffer): Pkt[] {
  const out: Pkt[] = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const head = buf.subarray(off, off + 4).toString('ascii');
    if (head === '0000') {
      out.push({ kind: 'flush', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (head === '0001') {
      out.push({ kind: 'delim', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    const len = parseInt(head, 16);
    if (!Number.isFinite(len) || len < 4 || off + len > buf.length) break;
    out.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return out;
}

// ---------------------------------------------------------------------------
// git objects: trees, commits, tags
// ---------------------------------------------------------------------------

type ObjType = 'commit' | 'tree' | 'blob' | 'tag';

interface GitObj {
  type: ObjType;
  data: Buffer;
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const space = data.indexOf(0x20, off);
    const nul = data.indexOf(0x00, space + 1);
    if (space < 0 || nul < 0 || nul + 21 > data.length) break;
    entries.push({
      mode: data.subarray(off, space).toString('ascii'),
      name: data.subarray(space + 1, nul).toString('utf8'),
      oid: data.subarray(nul + 1, nul + 21).toString('hex'),
    });
    off = nul + 21;
  }
  return entries;
}

function compareTreeNames(a: TreeEntry, b: TreeEntry): number {
  const left = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
  const right = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
  return Buffer.compare(left, right);
}

function buildTree(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort(compareTreeNames);
  const parts: Buffer[] = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(data: Buffer): CommitView {
  const blank = data.indexOf('\n\n');
  const headerEnd = blank < 0 ? data.length : blank;
  const message = blank < 0 ? '' : data.subarray(blank + 2).toString('utf8');
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of data.subarray(0, headerEnd).toString('utf8').split('\n')) {
    if (!line) continue;
    const sp = line.indexOf(' ');
    const key = sp < 0 ? line : line.slice(0, sp);
    const value = sp < 0 ? '' : line.slice(sp + 1);
    if (key === 'tree') tree = value;
    else if (key === 'parent') parents.push(value);
    else if (key === 'author') author = value;
    else if (key === 'committer') committer = value;
  }
  return { tree, parents, author, committer, message };
}

function buildCommit(tree: string, parents: string[], message: string, timestamp = FIXED_EPOCH): Buffer {
  const who = `${FORGE_IDENTITY} ${timestamp} +0000`;
  const lines = [`tree ${tree}`];
  for (const p of parents) lines.push(`parent ${p}`);
  lines.push(`author ${who}`, `committer ${who}`, '');
  return Buffer.from(`${lines.join('\n')}\n${message}`, 'utf8');
}

function parseTag(data: Buffer): { object: string; type: string; tag: string; tagger: string; message: string } {
  const blank = data.indexOf('\n\n');
  const headerEnd = blank < 0 ? data.length : blank;
  const headers = new Map<string, string>();
  for (const line of data.subarray(0, headerEnd).toString('utf8').split('\n')) {
    const sp = line.indexOf(' ');
    if (sp < 0) continue;
    headers.set(line.slice(0, sp), line.slice(sp + 1));
  }
  return {
    object: headers.get('object') ?? '',
    type: headers.get('type') ?? '',
    tag: headers.get('tag') ?? '',
    tagger: headers.get('tagger') ?? '',
    message: blank < 0 ? '' : data.subarray(blank + 2).toString('utf8'),
  };
}

// ---------------------------------------------------------------------------
// packfiles
// ---------------------------------------------------------------------------

const TYPE_CODE: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function writePackObjectHeader(type: ObjType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

/** Build a packfile from plain objects (no deltas). Deterministic for a given order. */
function writePack(objects: GitObj[]): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  parts.push(header);
  for (const o of objects) {
    parts.push(writePackObjectHeader(o.type, o.data.length));
    parts.push(deflateSync(o.data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

function readVarintSize(buf: Buffer, start: number): { size: number; next: number; first: number } {
  let byte = buf[start]!;
  const first = byte;
  let size = byte & 0x0f;
  let shift = 4;
  let off = start + 1;
  while (byte & 0x80) {
    byte = buf[off++]!;
    size += (byte & 0x7f) * 2 ** shift;
    shift += 7;
  }
  return { size, next: off, first };
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let off = 0;
  const readSize = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const b = delta[off++]!;
      value += (b & 0x7f) * 2 ** shift;
      shift += 7;
      if (!(b & 0x80)) break;
    }
    return value;
  };
  const sourceSize = readSize();
  const targetSize = readSize();
  if (sourceSize !== base.length) throw new Error('delta base size mismatch');
  const out = Buffer.allocUnsafe(targetSize);
  let written = 0;
  while (off < delta.length) {
    const op = delta[off++]!;
    if (op & 0x80) {
      let copyOff = 0;
      let copySize = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit++) {
        if (op & (1 << bit)) copyOff += delta[off++]! * 2 ** shift;
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit++) {
        if (op & (1 << bit)) copySize += delta[off++]! * 2 ** shift;
        shift += 8;
      }
      if (copySize === 0) copySize = 0x10000;
      base.copy(out, written, copyOff, copyOff + copySize);
      written += copySize;
    } else if (op !== 0) {
      const n = op & 0x7f;
      delta.copy(out, written, off, off + n);
      off += n;
      written += n;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  if (written !== targetSize) throw new Error('delta size mismatch');
  return out;
}

interface PackEntry {
  offset: number;
  typeCode: number;
  size: number;
  data: Buffer;
  baseOffset?: number;
  baseOid?: string;
}

/** Parse a packfile, resolving OFS/REF deltas. Returns oid -> object. */
function readPack(pack: Buffer, resolveBase?: (oid: string) => GitObj | undefined): Map<string, GitObj> {
  if (pack.length < 32 || pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('bad pack header');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const count = pack.readUInt32BE(8);
  const trailerStart = pack.length - 20;
  const raw: PackEntry[] = [];
  const byOffset = new Map<number, PackEntry>();
  let off = 12;
  for (let i = 0; i < count; i++) {
    const entryOffset = off;
    const header = readVarintSize(pack, off);
    off = header.next;
    const typeCode = (header.first >> 4) & 0x07;
    const entry: PackEntry = { offset: entryOffset, typeCode, size: header.size, data: Buffer.alloc(0) };
    if (typeCode === 6) {
      let byte = pack[off]!;
      off += 1;
      let value = byte & 0x7f;
      while (byte & 0x80) {
        byte = pack[off++]!;
        value = ((value + 1) * 128) + (byte & 0x7f);
      }
      entry.baseOffset = entryOffset - value;
    } else if (typeCode === 7) {
      entry.baseOid = pack.subarray(off, off + 20).toString('hex');
      off += 20;
    } else if (!CODE_TYPE[typeCode]) {
      throw new Error(`unknown pack type ${typeCode}`);
    }
    const inflated = inflateSync(pack.subarray(off, trailerStart), { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
    if (inflated.buffer.length !== header.size) throw new Error('pack entry size mismatch');
    entry.data = inflated.buffer;
    off += inflated.engine.bytesWritten;
    raw.push(entry);
    byOffset.set(entryOffset, entry);
  }
  const objects = new Map<string, GitObj>();
  const resolvedByOid = new Map<string, PackEntry>();
  const resolving = new Set<number>();
  const resolve = (entry: PackEntry): { type: ObjType; data: Buffer; oid: string } => {
    const cached = (entry as unknown as { _r?: { type: ObjType; data: Buffer; oid: string } })._r;
    if (cached) return cached;
    if (resolving.has(entry.offset)) throw new Error('delta cycle');
    resolving.add(entry.offset);
    let type: ObjType;
    let data: Buffer;
    if (entry.typeCode === 6) {
      const baseEntry = byOffset.get(entry.baseOffset!);
      if (!baseEntry) throw new Error('ofs-delta base missing');
      const base = resolve(baseEntry);
      type = base.type;
      data = applyDelta(base.data, entry.data);
    } else if (entry.typeCode === 7) {
      const baseEntry = resolvedByOid.get(entry.baseOid!);
      if (baseEntry) {
        const base = resolve(baseEntry);
        type = base.type;
        data = applyDelta(base.data, entry.data);
      } else {
        const external = resolveBase?.(entry.baseOid!);
        if (!external) throw new Error('ref-delta base missing');
        type = external.type;
        data = applyDelta(external.data, entry.data);
      }
    } else {
      type = CODE_TYPE[entry.typeCode]!;
      data = entry.data;
    }
    const oid = hashObject(type, data);
    const out = { type, data, oid };
    (entry as unknown as { _r?: unknown })._r = out;
    resolvedByOid.set(oid, entry);
    resolving.delete(entry.offset);
    return out;
  };
  for (const entry of raw) {
    const r = resolve(entry);
    if (!objects.has(r.oid)) objects.set(r.oid, { type: r.type, data: r.data });
  }
  return objects;
}

// ---------------------------------------------------------------------------
// object graph helpers (per repo)
// ---------------------------------------------------------------------------

type ObjStore = Map<string, GitObj>;

/** All oids reachable from tips (commits, trees, blobs, tags), iterative. */
function collectReachable(store: ObjStore, tips: string[]): Set<string> {
  const seen = new Set<string>();
  const stack = [...tips];
  while (stack.length > 0) {
    const oid = stack.pop()!;
    if (seen.has(oid)) continue;
    const obj = store.get(oid);
    if (!obj) continue;
    seen.add(oid);
    if (obj.type === 'commit') {
      const c = parseCommit(obj.data);
      stack.push(c.tree);
      for (const p of c.parents) stack.push(p);
    } else if (obj.type === 'tree') {
      for (const e of parseTree(obj.data)) stack.push(e.oid);
    } else if (obj.type === 'tag') {
      stack.push(parseTag(obj.data).object);
    }
  }
  return seen;
}

/** Is `anc` an ancestor of (or equal to) `tip`? Walks commit parents only. */
function isAncestor(store: ObjStore, anc: string, tip: string): boolean {
  if (anc === tip) return true;
  const seen = new Set<string>();
  const stack = [tip];
  while (stack.length > 0) {
    const oid = stack.pop()!;
    if (oid === anc) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = store.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    for (const p of parseCommit(obj.data).parents) stack.push(p);
  }
  return false;
}

/** Commits reachable from tip, newest-first (DFS pre-order from the tip). */
function commitsFrom(store: ObjStore, tip: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const stack = [tip];
  while (stack.length > 0) {
    const oid = stack.pop()!;
    if (seen.has(oid)) continue;
    const obj = store.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    seen.add(oid);
    out.push(oid);
    const parents = parseCommit(obj.data).parents;
    for (let i = parents.length - 1; i >= 0; i--) stack.push(parents[i]!);
  }
  return out;
}

/** Flatten a tree into path -> {oid, mode}. */
function treeToMap(store: ObjStore, treeOid: string, prefix = '', out = new Map<string, { oid: string; mode: string }>()): Map<string, { oid: string; mode: string }> {
  const obj = store.get(treeOid);
  if (!obj || obj.type !== 'tree') return out;
  for (const e of parseTree(obj.data)) {
    const path = prefix === '' ? e.name : `${prefix}/${e.name}`;
    if (e.mode === '40000') treeToMap(store, e.oid, path, out);
    else out.set(path, { oid: e.oid, mode: e.mode });
  }
  return out;
}

interface TreeNode {
  files: Map<string, { oid: string; mode: string }>;
  dirs: Map<string, TreeNode>;
}

/** Build (and store) nested trees from a flat file map. Returns the root tree oid. */
function mapToTree(store: ObjStore, files: Map<string, { oid: string; mode: string }>): string {
  const make = (): TreeNode => ({ files: new Map(), dirs: new Map() });
  const root = make();
  for (const [path, entry] of files) {
    const segs = path.split('/');
    let node = root;
    for (let i = 0; i < segs.length - 1; i++) {
      const name = segs[i]!;
      if (!node.dirs.has(name)) node.dirs.set(name, make());
      node = node.dirs.get(name)!;
    }
    node.files.set(segs[segs.length - 1]!, entry);
  }
  const build = (node: TreeNode): string => {
    const entries: TreeEntry[] = [];
    for (const [name, e] of node.files) entries.push({ mode: e.mode, name, oid: e.oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    const data = buildTree(entries);
    const oid = hashObject('tree', data);
    if (!store.has(oid)) store.set(oid, { type: 'tree', data });
    return oid;
  };
  return build(root);
}

/** First common ancestor of a and b (walks a's history; linear histories dominate). */
function mergeBase(store: ObjStore, a: string, b: string): string | null {
  const bAnc = new Set(commitsFrom(store, b));
  for (const oid of commitsFrom(store, a)) {
    if (bAnc.has(oid)) return oid;
  }
  return null;
}

/** Peel a tag object to its commit (recursively). */
function peelToCommit(store: ObjStore, oid: string): string {
  let cur = oid;
  for (let i = 0; i < 10; i++) {
    const obj = store.get(cur);
    if (!obj || obj.type !== 'tag') return cur;
    cur = parseTag(obj.data).object;
  }
  return cur;
}

// ---------------------------------------------------------------------------
// the store
// ---------------------------------------------------------------------------

interface Label {
  id: number;
  name: string;
  color: string;
  description: string;
}

interface IssueComment {
  id: number;
  body: string;
  user: string;
}

interface Issue {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: Label[];
  comments: IssueComment[];
  user: string;
  createdAt: string;
  updatedAt: string;
  closedAt: string | null;
  json: string; // cached serialized REST form
  jsonBuf: Buffer; // same form, pre-encoded: sending it skips per-request UTF-8 encoding
}

interface PullRequest {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  user: string;
  createdAt: string;
  updatedAt: string;
  json: string; // cached serialized REST form
  jsonBuf: Buffer; // same form, pre-encoded: sending it skips per-request UTF-8 encoding
}

interface Repo {
  id: number;
  name: string;
  owner: string | null; // null until the token owner's login is learned
  fullName: string;
  private: boolean;
  description: string;
  defaultBranch: string;
  objects: ObjStore;
  refs: Map<string, string>; // refname -> oid
  issues: Issue[];
  issuesByNumber: Map<number, Issue>;
  pulls: PullRequest[];
  pullsByNumber: Map<number, PullRequest>;
  labels: Map<string, Label>;
  nextNumber: number; // shared issue/PR counter
  nextCommentId: number;
  version: number; // bumped on any git/REST mutation; invalidates caches
  repoJson: string; // cached serialized REST form
  repoJsonBuf: Buffer; // same form, pre-encoded
  adV0: Buffer | null; // cached v0 upload-pack advertisement
  adV2: Buffer | null; // cached v2 upload-pack advertisement
  adRecv: Buffer | null; // cached receive-pack advertisement
  lsCache: Map<string, Buffer>; // ls-refs responses by args key
  packCache: Map<string, Buffer>; // fetch pack bytes by request key
}

const reposByName = new Map<string, Repo>();
let nextRepoId = 1;
let nextLabelId = 1;
let nextGlobalId = 1;
let learnedOwner: string | null = null;

function learnOwner(owner: string): void {
  if (learnedOwner !== null) return;
  learnedOwner = owner;
  for (const repo of reposByName.values()) {
    if (repo.owner === null) {
      repo.owner = owner;
      repo.fullName = `${owner}/${repo.name}`;
      repo.repoJson = '';
    }
  }
}

function ownerLogin(): string {
  return learnedOwner ?? '';
}

function globalId(kind: string, ...parts: (string | number)[]): string {
  return Buffer.from(`forge:${kind}:${parts.join(':')}`, 'utf8').toString('base64');
}

function decodeGlobalId(id: string): { kind: string; parts: (string | number)[] } | null {
  try {
    const text = Buffer.from(id, 'base64').toString('utf8');
    if (!text.startsWith('forge:')) return null;
    const segs = text.split(':');
    return { kind: segs[1] ?? '', parts: segs.slice(2).map((p) => (/^\d+$/.test(p) ? Number(p) : p)) };
  } catch {
    return null;
  }
}

function newRepo(name: string, isPrivate: boolean, description: string): Repo {
  const repo: Repo = {
    id: nextRepoId++,
    name,
    owner: learnedOwner,
    fullName: `${learnedOwner ?? ''}/${name}`,
    private: isPrivate,
    description,
    defaultBranch: 'main',
    objects: new Map(),
    refs: new Map(),
    issues: [],
    issuesByNumber: new Map(),
    pulls: [],
    pullsByNumber: new Map(),
    labels: new Map(),
    nextNumber: 1,
    nextCommentId: 1,
    version: 0,
    repoJson: '',
    repoJsonBuf: EMPTY_BODY,
    adV0: null,
    adV2: null,
    adRecv: null,
    lsCache: new Map(),
    packCache: new Map(),
  };
  reposByName.set(name, repo);
  return repo;
}

function bump(repo: Repo): void {
  repo.version += 1;
  repo.adV0 = null;
  repo.adV2 = null;
  repo.adRecv = null;
  repo.lsCache.clear();
  repo.packCache.clear();
  repo.repoJson = '';
  repo.repoJsonBuf = EMPTY_BODY;
}

function findRepo(name: string): Repo | undefined {
  return reposByName.get(name);
}

/** Resolve a ref name or oid to a commit oid (branch first, then raw oid). */
function resolveRef(repo: Repo, ref: string): string | null {
  if (repo.refs.has(`refs/heads/${ref}`)) return repo.refs.get(`refs/heads/${ref}`)!;
  if (repo.refs.has(ref)) return repo.refs.get(ref)!;
  if (isOid(ref) && repo.objects.has(ref)) return ref;
  return null;
}

function defaultTip(repo: Repo): string | null {
  return repo.refs.get(`refs/heads/${repo.defaultBranch}`) ?? null;
}

// ---------------------------------------------------------------------------
// REST shapes (extra fields are harmless: the suite checks required props only)
// ---------------------------------------------------------------------------

function userJson(login: string): Record<string, unknown> {
  return { login, id: 1000, node_id: globalId('User', login), avatar_url: '', html_url: '', type: 'User', site_admin: false };
}

function repoJsonOf(repo: Repo): Record<string, unknown> {
  const owner = repo.owner ?? learnedOwner ?? '';
  return {
    id: repo.id,
    node_id: globalId('Repository', repo.id),
    name: repo.name,
    full_name: `${owner}/${repo.name}`,
    owner: userJson(owner),
    private: repo.private,
    html_url: '',
    description: repo.description,
    fork: false,
    url: `/api/v3/repos/${owner}/${repo.name}`,
    created_at: FIXED_ISO,
    updated_at: FIXED_ISO,
    pushed_at: FIXED_ISO,
    homepage: null,
    size: 0,
    stargazers_count: 0,
    watchers_count: 0,
    language: null,
    has_issues: true,
    has_projects: true,
    has_wiki: true,
    has_pages: false,
    has_downloads: true,
    archived: false,
    disabled: false,
    visibility: repo.private ? 'private' : 'public',
    default_branch: repo.defaultBranch,
    permissions: { admin: true, maintain: true, push: true, triage: true, pull: true },
    license: null,
    topics: [],
  };
}

function cachedRepoJson(repo: Repo): string {
  if (repo.repoJson === '') repo.repoJson = JSON.stringify(repoJsonOf(repo));
  return repo.repoJson;
}

function cachedRepoJsonBuf(repo: Repo): Buffer {
  if (repo.repoJsonBuf.length === 0) repo.repoJsonBuf = Buffer.from(cachedRepoJson(repo), 'utf8');
  return repo.repoJsonBuf;
}

function labelJsonOf(label: Label): Record<string, unknown> {
  return { id: label.id, node_id: globalId('Label', label.id), name: label.name, color: label.color, description: label.description, default: false };
}

function issueJsonOf(repo: Repo, issue: Issue): Record<string, unknown> {
  const owner = repo.owner ?? learnedOwner ?? '';
  return {
    id: issue.id,
    node_id: globalId('Issue', repo.id, issue.number),
    url: `/api/v3/repos/${owner}/${repo.name}/issues/${issue.number}`,
    repository_url: `/api/v3/repos/${owner}/${repo.name}`,
    html_url: '',
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    locked: false,
    user: userJson(issue.user),
    labels: issue.labels.map(labelJsonOf),
    assignee: null,
    assignees: [],
    milestone: null,
    comments: issue.comments.length,
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    closed_at: issue.closedAt,
    author_association: 'OWNER',
  };
}

function refreshIssueJson(repo: Repo, issue: Issue): void {
  issue.json = JSON.stringify(issueJsonOf(repo, issue));
  issue.jsonBuf = Buffer.from(issue.json, 'utf8');
}

function pullJsonOf(repo: Repo, pr: PullRequest): Record<string, unknown> {
  const owner = repo.owner ?? learnedOwner ?? '';
  const base = {
    id: pr.id,
    node_id: globalId('PullRequest', repo.id, pr.number),
    url: `/api/v3/repos/${owner}/${repo.name}/pulls/${pr.number}`,
    html_url: '',
    number: pr.number,
    title: pr.title,
    body: pr.body,
    state: pr.state,
    locked: false,
    draft: false,
    merged: pr.merged,
    mergeable: true,
    mergeable_state: pr.merged ? 'clean' : 'clean',
    merged_at: pr.mergedAt,
    merge_commit_sha: pr.mergeCommitSha,
    user: userJson(pr.user),
    head: { label: `${owner}:${pr.headRef}`, ref: pr.headRef, sha: pr.headSha, user: userJson(owner), repo: repoJsonOf(repo) },
    base: { label: `${owner}:${pr.baseRef}`, ref: pr.baseRef, sha: pr.baseSha, user: userJson(owner), repo: repoJsonOf(repo) },
    created_at: pr.createdAt,
    updated_at: pr.updatedAt,
    closed_at: pr.state === 'closed' ? FIXED_ISO : null,
    author_association: 'OWNER',
  };
  return base;
}

function refreshPullJson(repo: Repo, pr: PullRequest): void {
  pr.json = JSON.stringify(pullJsonOf(repo, pr));
  pr.jsonBuf = Buffer.from(pr.json, 'utf8');
}

/** Create an issue on a repo (labels must already exist). Returns the issue or an error message. */
function createIssueOn(repo: Repo, title: string, body: string, labelNames: string[] = []): { issue?: Issue; error?: string } {
  const labels: Label[] = [];
  for (const name of labelNames) {
    const label = repo.labels.get(name);
    if (!label) return { error: `Label '${name}' does not exist` };
    labels.push(label);
  }
  const number = repo.nextNumber++;
  const issue: Issue = {
    id: nextGlobalId++,
    number,
    title,
    body: body ?? '',
    state: 'open',
    labels,
    comments: [],
    user: ownerLogin(),
    createdAt: FIXED_ISO,
    updatedAt: FIXED_ISO,
    closedAt: null,
    json: '',
    jsonBuf: EMPTY_BODY,
  };
  repo.issues.push(issue);
  repo.issuesByNumber.set(number, issue);
  refreshIssueJson(repo, issue);
  return { issue };
}

/** Line diff counts (LCS on lines; files here are small). */
function lineDiff(oldText: string, newText: string): { additions: number; deletions: number } {
  const a = oldText === '' ? [] : oldText.split('\n');
  const b = newText === '' ? [] : newText.split('\n');
  if (a.length === 0) return { additions: b.length, deletions: 0 };
  if (b.length === 0) return { additions: 0, deletions: a.length };
  // LCS length via two rows.
  let prev = new Array<number>(b.length + 1).fill(0);
  let cur = new Array<number>(b.length + 1).fill(0);
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      cur[j] = a[i - 1] === b[j - 1] ? prev[j - 1] + 1 : Math.max(prev[j]!, cur[j - 1]!);
    }
    const tmp = prev;
    prev = cur;
    cur = tmp;
    cur.fill(0);
  }
  const lcs = prev[b.length]!;
  return { additions: b.length - lcs, deletions: a.length - lcs };
}

interface FileChange {
  filename: string;
  status: 'added' | 'modified' | 'removed';
  additions: number;
  deletions: number;
  changes: number;
}

/** Files changed between base tree and head tree (via their merge-base when known). */
function diffFiles(repo: Repo, baseOid: string, headOid: string): FileChange[] {
  const baseCommit = repo.objects.get(baseOid);
  const headCommit = repo.objects.get(headOid);
  if (!baseCommit || !headCommit || baseCommit.type !== 'commit' || headCommit.type !== 'commit') return [];
  const baseTree = parseCommit(baseCommit.data).tree;
  const headTree = parseCommit(headCommit.data).tree;
  const baseMap = treeToMap(repo.objects, baseTree);
  const headMap = treeToMap(repo.objects, headTree);
  const out: FileChange[] = [];
  const paths = new Set([...baseMap.keys(), ...headMap.keys()]);
  for (const path of paths) {
    const b = baseMap.get(path);
    const h = headMap.get(path);
    if (b && !h) {
      const oldText = repo.objects.get(b.oid)?.data.toString('utf8') ?? '';
      const d = lineDiff(oldText, '');
      out.push({ filename: path, status: 'removed', additions: 0, deletions: d.deletions, changes: d.deletions });
    } else if (!b && h) {
      const newText = repo.objects.get(h.oid)?.data.toString('utf8') ?? '';
      const d = lineDiff('', newText);
      out.push({ filename: path, status: 'added', additions: d.additions, deletions: 0, changes: d.additions });
    } else if (b && h && b.oid !== h.oid) {
      const oldText = repo.objects.get(b.oid)?.data.toString('utf8') ?? '';
      const newText = repo.objects.get(h.oid)?.data.toString('utf8') ?? '';
      const d = lineDiff(oldText, newText);
      out.push({ filename: path, status: 'modified', additions: d.additions, deletions: d.deletions, changes: d.additions + d.deletions });
    }
  }
  out.sort((x, y) => (x.filename < y.filename ? -1 : 1));
  return out;
}

/** Would merging head into base conflict? (same path changed both sides, different result) */
function mergeConflict(repo: Repo, baseOid: string, headOid: string): boolean {
  const base = mergeBase(repo.objects, headOid, baseOid);
  if (base === null) return false;
  const baseCommit = repo.objects.get(base);
  if (!baseCommit) return false;
  const baseTree = parseCommit(baseCommit.data).tree;
  const mbMap = treeToMap(repo.objects, baseTree);
  const baseTipCommit = repo.objects.get(baseOid);
  const headTipCommit = repo.objects.get(headOid);
  if (!baseTipCommit || !headTipCommit) return false;
  const baseTipMap = treeToMap(repo.objects, parseCommit(baseTipCommit.data).tree);
  const headTipMap = treeToMap(repo.objects, parseCommit(headTipCommit.data).tree);
  const paths = new Set([...mbMap.keys(), ...baseTipMap.keys(), ...headTipMap.keys()]);
  for (const path of paths) {
    const mb = mbMap.get(path)?.oid;
    const bt = baseTipMap.get(path)?.oid;
    const ht = headTipMap.get(path)?.oid;
    const changedBase = bt !== mb;
    const changedHead = ht !== mb;
    if (changedBase && changedHead && bt !== ht) return true;
  }
  return false;
}

/** Squash-merge a PR onto its base branch. Returns the merge commit oid or null on conflict. */
function squashMerge(repo: Repo, pr: PullRequest): string | null {
  const baseTip = repo.refs.get(`refs/heads/${pr.baseRef}`);
  const headTip = repo.refs.get(`refs/heads/${pr.headRef}`);
  if (!baseTip || !headTip) return null;
  if (mergeConflict(repo, baseTip, headTip)) return null;
  const base = mergeBase(repo.objects, headTip, baseTip);
  const mbTree = base === null ? null : parseCommit(repo.objects.get(base)!.data).tree;
  const mbMap = mbTree === null ? new Map() : treeToMap(repo.objects, mbTree);
  const baseTipMap = treeToMap(repo.objects, parseCommit(repo.objects.get(baseTip)!.data).tree);
  const headTipMap = treeToMap(repo.objects, parseCommit(repo.objects.get(headTip)!.data).tree);
  // Result = base tip tree + head's changes relative to the merge-base.
  const result = new Map(baseTipMap);
  for (const [path, entry] of headTipMap) {
    if (mbMap.get(path)?.oid !== entry.oid) result.set(path, entry);
  }
  for (const path of mbMap.keys()) {
    if (!headTipMap.has(path) && mbMap.get(path)?.oid !== baseTipMap.get(path)?.oid) {
      // deleted on head side and unchanged on base side
      if (baseTipMap.get(path)?.oid === mbMap.get(path)?.oid) result.delete(path);
    }
  }
  const treeOid = mapToTree(repo.objects, result);
  const message = `Merge pull request #${pr.number} from ${pr.headRef}\n`;
  const commitData = buildCommit(treeOid, [baseTip], message);
  const commitOid = hashObject('commit', commitData);
  repo.objects.set(commitOid, { type: 'commit', data: commitData });
  repo.refs.set(`refs/heads/${pr.baseRef}`, commitOid);
  pr.merged = true;
  pr.state = 'closed';
  pr.mergedAt = FIXED_ISO;
  pr.mergeCommitSha = commitOid;
  pr.baseSha = commitOid;
  pr.updatedAt = FIXED_ISO;
  bump(repo);
  refreshPullJson(repo, pr);
  return commitOid;
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

function sendJson(res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}): void {
  const text = typeof body === 'string' ? body : `${JSON.stringify(body)}\n`;
  res.writeHead(status, { 'content-type': JSON_TYPE, 'content-length': Buffer.byteLength(text), 'x-github-request-id': nextRequestId(), ...extra });
  res.end(text);
}

function sendJsonText(res: ServerResponse, status: number, text: string | Buffer, extra: Record<string, string> = {}): void {
  const body = typeof text === 'string' ? Buffer.from(text, 'utf8') : text;
  res.writeHead(status, { 'content-type': JSON_TYPE, 'content-length': body.length, 'x-github-request-id': nextRequestId(), ...extra });
  res.end(body);
}

function sendRaw(res: ServerResponse, status: number, contentType: string, body: Buffer, extra: Record<string, string> = {}): void {
  res.writeHead(status, { 'content-type': contentType, 'content-length': body.length, 'x-github-request-id': nextRequestId(), ...extra });
  res.end(body);
}

function errJson(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function parseJsonBody(buf: Buffer): { ok: true; value: unknown } | { ok: false } {
  if (buf.length === 0) return { ok: true, value: {} };
  try {
    return { ok: true, value: JSON.parse(buf.toString('utf8')) };
  } catch {
    return { ok: false };
  }
}

function decodeSeg(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

function paginate<T>(items: readonly T[], query: URLSearchParams): { page: T[]; link: string | null; total: number } {
  const perPageRaw = Number(query.get('per_page') ?? '30');
  const pageRaw = Number(query.get('page') ?? '1');
  const perPage = Number.isFinite(perPageRaw) && perPageRaw > 0 ? Math.min(100, Math.trunc(perPageRaw)) : 30;
  const page = Number.isFinite(pageRaw) && pageRaw > 0 ? Math.trunc(pageRaw) : 1;
  const start = (page - 1) * perPage;
  const slice = items.slice(start, start + perPage);
  return { page: slice as T[], link: null, total: items.length };
}

function linkHeader(req: IncomingMessage, query: URLSearchParams, total: number): string | null {
  const perPageRaw = Number(query.get('per_page') ?? '30');
  const pageRaw = Number(query.get('page') ?? '1');
  const perPage = Number.isFinite(perPageRaw) && perPageRaw > 0 ? Math.min(100, Math.trunc(perPageRaw)) : 30;
  const page = Number.isFinite(pageRaw) && pageRaw > 0 ? Math.trunc(pageRaw) : 1;
  if (page * perPage >= total) return null;
  const host = req.headers.host ?? 'localhost';
  const base = `http://${host}${new URL(req.url ?? '/', 'http://x').pathname}`;
  const next = new URL(base);
  next.searchParams.set('page', String(page + 1));
  next.searchParams.set('per_page', String(perPage));
  const lastPage = Math.max(1, Math.ceil(total / perPage));
  const last = new URL(base);
  last.searchParams.set('page', String(lastPage));
  last.searchParams.set('per_page', String(perPage));
  return `<${next.toString()}>; rel="next", <${last.toString()}>; rel="last"`;
}

function authOk(req: IncomingMessage): boolean {
  if (TOKEN === '') return true;
  const h = req.headers.authorization ?? '';
  return h === BEARER;
}

// ---------------------------------------------------------------------------
// contents commits (the REST way to write files)
// ---------------------------------------------------------------------------

interface ContentPutResult {
  status: number;
  commitSha?: string;
  contentSha?: string;
  message?: string;
}

/** Commit one file change on a branch; creates the branch from the default tip when missing. */
function putContentFile(repo: Repo, path: string, contentB64: string, message: string, branch: string | undefined, sha: string | undefined): ContentPutResult {
  const branchName = branch ?? repo.defaultBranch;
  let tip = repo.refs.get(`refs/heads/${branchName}`);
  if (tip === undefined) {
    // Create the branch from the default branch tip (or unborn).
    const base = branchName === repo.defaultBranch ? undefined : defaultTip(repo);
    if (base !== undefined) {
      repo.refs.set(`refs/heads/${branchName}`, base);
      tip = base;
    }
  }
  const data = b64decode(contentB64);
  const blobOid = hashObject('blob', data);
  repo.objects.set(blobOid, { type: 'blob', data });
  let files = new Map<string, { oid: string; mode: string }>();
  let parents: string[] = [];
  if (tip !== undefined) {
    const commit = repo.objects.get(tip);
    if (!commit || commit.type !== 'commit') return { status: 422, message: 'Invalid branch tip' };
    files = treeToMap(repo.objects, parseCommit(commit.data).tree);
    parents = [tip];
    const existing = files.get(path);
    if (existing) {
      if (sha === undefined) return { status: 422, message: 'sha is required to update a file' };
      if (sha.toLowerCase() !== existing.oid.toLowerCase()) return { status: 409, message: 'sha does not match the current file' };
    }
  }
  const isUpdate = files.has(path);
  files.set(path, { oid: blobOid, mode: '100644' });
  const treeOid = mapToTree(repo.objects, files);
  const commitData = buildCommit(treeOid, parents, message.endsWith('\n') ? message : `${message}\n`);
  const commitOid = hashObject('commit', commitData);
  repo.objects.set(commitOid, { type: 'commit', data: commitData });
  repo.refs.set(`refs/heads/${branchName}`, commitOid);
  bump(repo);
  return { status: isUpdate ? 200 : 201, commitSha: commitOid, contentSha: blobOid };
}

function deleteContentFile(repo: Repo, path: string, message: string, branch: string | undefined, sha: string | undefined): ContentPutResult {
  const branchName = branch ?? repo.defaultBranch;
  const tip = repo.refs.get(`refs/heads/${branchName}`);
  if (tip === undefined) return { status: 404, message: 'Not Found' };
  const commit = repo.objects.get(tip);
  if (!commit || commit.type !== 'commit') return { status: 404, message: 'Not Found' };
  const files = treeToMap(repo.objects, parseCommit(commit.data).tree);
  const existing = files.get(path);
  if (!existing) return { status: 404, message: 'Not Found' };
  if (sha !== undefined && sha.toLowerCase() !== existing.oid.toLowerCase()) return { status: 409, message: 'sha does not match the current file' };
  files.delete(path);
  const treeOid = mapToTree(repo.objects, files);
  const commitData = buildCommit(treeOid, [tip], message.endsWith('\n') ? message : `${message}\n`);
  const commitOid = hashObject('commit', commitData);
  repo.objects.set(commitOid, { type: 'commit', data: commitData });
  repo.refs.set(`refs/heads/${branchName}`, commitOid);
  bump(repo);
  return { status: 200, commitSha: commitOid };
}

// ---------------------------------------------------------------------------
// REST v3
// ---------------------------------------------------------------------------

function repoRouteOwner(owner: string): boolean {
  if (learnedOwner === null) {
    learnOwner(owner);
    return true;
  }
  return owner === learnedOwner;
}

async function handleRest(req: IncomingMessage, res: ServerResponse, segs: string[], query: URLSearchParams, bodyBuf: Buffer): Promise<boolean> {
  const method = req.method ?? 'GET';
  const first = segs[0] ?? '';

  // API root
  if (segs.length === 0) {
    if (method !== 'GET') return false;
    sendJson(res, 200, {
      current_user_url: '/api/v3/user',
      current_user_authorizations_html_url: '',
      authorizations_url: '/api/v3/authorizations',
      code_search_url: '/api/v3/search/code?q={query}',
      commit_search_url: '/api/v3/search/commits?q={query}',
      emails_url: '/api/v3/user/emails',
      emojis_url: '/api/v3/emojis',
      events_url: '/api/v3/events',
      feeds_url: '/api/v3/feeds',
      followers_url: '/api/v3/user/followers',
      following_url: '/api/v3/user/following{/target}',
      gists_url: '/api/v3/gists{/gist_id}',
      hub_url: '/api/v3/hub',
      issue_search_url: '/api/v3/search/issues?q={query}',
      issues_url: '/api/v3/issues',
      keys_url: '/api/v3/user/keys',
      label_search_url: '/api/v3/search/labels?q={query}',
      notifications_url: '/api/v3/notifications',
      organization_repositories_url: '/api/v3/orgs/{org}/repos{?type,page,per_page,sort}',
      organization_url: '/api/v3/orgs/{org}',
      public_gists_url: '/api/v3/gists/public',
      rate_limit_url: '/api/v3/rate_limit',
      repository_url: '/api/v3/repos/{owner}/{repo}',
      repository_search_url: '/api/v3/search/repositories?q={query}',
      current_user_repositories_url: '/api/v3/user/repos{?type,page,per_page,sort}',
      starred_url: '/api/v3/user/starred{/owner}{/repo}',
      starred_gists_url: '/api/v3/gists/starred',
      topic_search_url: '/api/v3/search/topics?q={query}',
      user_url: '/api/v3/users/{user}',
      user_organizations_url: '/api/v3/user/orgs',
      user_repositories_url: '/api/v3/users/{user}/repos{?type,page,per_page,sort}',
      user_search_url: '/api/v3/search/users?q={query}',
    }, { 'x-oauth-scopes': 'repo, read:org', 'x-accepted-oauth-scopes': 'repo, read:org' });
    return true;
  }

  if (first === 'meta' && segs.length === 1) {
    if (method !== 'GET') return false;
    sendJson(res, 200, { verifiable_password_authentication: true, installed_version: '1.0.0', hooks: [], git: [], pages: [], importer: [], api: [] });
    return true;
  }

  if (first === 'rate_limit' && segs.length === 1) {
    if (method !== 'GET') return false;
    sendJson(res, 200, { resources: { core: { limit: 5000, remaining: 5000, reset: 1735689600, used: 0 } }, rate: { limit: 5000, remaining: 5000, reset: 1735689600, used: 0 } });
    return true;
  }

  if (first === 'user') {
    if (segs.length === 1) {
      if (method !== 'GET') return false;
      const login = learnedOwner ?? '';
      sendJson(res, 200, { ...userJson(login), name: login, email: null, bio: null, public_repos: reposByName.size, followers: 0, following: 0, created_at: FIXED_ISO, updated_at: FIXED_ISO });
      return true;
    }
    if (segs[1] === 'repos') {
      if (method === 'GET') {
        const all = [...reposByName.values()].sort((a, b) => a.id - b.id).map((r) => JSON.parse(cachedRepoJson(r)) as unknown);
        const { page } = paginate(all, query);
        const link = linkHeader(req, query, all.length);
        sendJson(res, 200, page, link === null ? {} : { link });
        return true;
      }
      if (method === 'POST') {
        const parsed = parseJsonBody(bodyBuf);
        if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return true; }
        const b = (parsed.value ?? {}) as Record<string, unknown>;
        const name = typeof b.name === 'string' ? b.name : '';
        if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(name)) { errJson(res, 422, 'Invalid repository name'); return true; }
        if (reposByName.has(name)) { errJson(res, 422, 'Repository already exists'); return true; }
        const repo = newRepo(name, b.private === true, typeof b.description === 'string' ? b.description : '');
        sendJson(res, 201, repoJsonOf(repo));
        return true;
      }
      return false;
    }
    return false;
  }

  if (first === 'repos' && segs.length >= 3) {
    const owner = decodeSeg(segs[1]!);
    const repoName = decodeSeg(segs[2]!);
    if (!repoRouteOwner(owner)) { errJson(res, 404, 'Not Found'); return true; }
    const repo = findRepo(repoName);
    const rest = segs.slice(3);

    if (rest.length === 0) {
      if (method === 'GET') {
        if (!repo) { errJson(res, 404, 'Not Found'); return true; }
        sendJsonText(res, 200, cachedRepoJsonBuf(repo));
        return true;
      }
      if (method === 'PATCH') {
        if (!repo) { errJson(res, 404, 'Not Found'); return true; }
        const parsed = parseJsonBody(bodyBuf);
        if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return true; }
        const b = (parsed.value ?? {}) as Record<string, unknown>;
        if (typeof b.description === 'string') repo.description = b.description;
        if (typeof b.private === 'boolean') repo.private = b.private;
        bump(repo);
        sendJson(res, 200, repoJsonOf(repo));
        return true;
      }
      if (method === 'DELETE') {
        if (!repo) { errJson(res, 404, 'Not Found'); return true; }
        reposByName.delete(repoName);
        res.writeHead(204, { 'content-type': JSON_TYPE, 'x-github-request-id': nextRequestId() });
        res.end();
        return true;
      }
      return false;
    }

    if (!repo) { errJson(res, 404, 'Not Found'); return true; }
    const sub = rest[0]!;

    if (sub === 'branches') {
      if (rest.length === 1 && method === 'GET') {
        const list: Record<string, unknown>[] = [];
        for (const [ref, sha] of [...repo.refs.entries()].sort()) {
          if (!ref.startsWith('refs/heads/')) continue;
          list.push({ name: ref.slice('refs/heads/'.length), commit: { sha, url: '' }, protected: false });
        }
        sendJson(res, 200, list);
        return true;
      }
      if (rest.length === 2 && method === 'GET') {
        const branch = decodeSeg(rest[1]!);
        const sha = repo.refs.get(`refs/heads/${branch}`);
        if (!sha) { errJson(res, 404, 'Not Found'); return true; }
        sendJson(res, 200, { name: branch, commit: { sha, url: '' }, protected: false });
        return true;
      }
      return false;
    }

    if (sub === 'commits') {
      if (rest.length === 1 && method === 'GET') {
        const ref = query.get('sha') ?? repo.defaultBranch;
        const tip = resolveRef(repo, ref);
        if (tip === null) { errJson(res, 404, 'Not Found'); return true; }
        const commits = commitsFrom(repo.objects, tip).map((sha) => {
          const c = parseCommit(repo.objects.get(sha)!.data);
          return { sha, commit: { message: c.message.replace(/\n$/, ''), author: { name: c.author, email: '', date: FIXED_ISO }, committer: { name: c.committer, email: '', date: FIXED_ISO } }, parents: c.parents.map((p) => ({ sha: p })) };
        });
        const { page } = paginate(commits, query);
        const link = linkHeader(req, query, commits.length);
        sendJson(res, 200, page, link === null ? {} : { link });
        return true;
      }
      return false;
    }

    if (sub === 'git' && rest[1] === 'refs') {
      if (method === 'POST' && rest.length === 2) {
        const parsed = parseJsonBody(bodyBuf);
        if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return true; }
        const b = (parsed.value ?? {}) as Record<string, unknown>;
        const ref = typeof b.ref === 'string' ? b.ref : '';
        const sha = typeof b.sha === 'string' ? b.sha : '';
        if (!ref.startsWith('refs/') || !isOid(sha) || !repo.objects.has(sha)) { errJson(res, 422, 'Invalid ref or sha'); return true; }
        if (repo.refs.has(ref)) { errJson(res, 422, 'Reference already exists'); return true; }
        repo.refs.set(ref, sha);
        bump(repo);
        sendJson(res, 201, { ref, node_id: globalId('Ref', repo.id, ref), url: '', object: { sha, type: repo.objects.get(sha)!.type, url: '' } });
        return true;
      }
      if (method === 'GET' && rest.length >= 3) {
        const refPath = rest.slice(2).map(decodeSeg).join('/');
        const fullRef = `refs/${refPath}`;
        const sha = repo.refs.get(fullRef);
        if (!sha) { errJson(res, 404, 'Not Found'); return true; }
        sendJson(res, 200, { ref: fullRef, node_id: globalId('Ref', repo.id, fullRef), url: '', object: { sha, type: repo.objects.get(sha)?.type ?? 'commit', url: '' } });
        return true;
      }
      return false;
    }

    if (sub === 'contents') {
      const path = rest.slice(1).map(decodeSeg).join('/');
      if (method === 'GET') {
        const ref = query.get('ref') ?? undefined;
        const tip = ref === undefined ? defaultTip(repo) : resolveRef(repo, ref);
        if (tip === null) { errJson(res, 404, 'Not Found'); return true; }
        const commit = repo.objects.get(tip);
        if (!commit || commit.type !== 'commit') { errJson(res, 404, 'Not Found'); return true; }
        const files = treeToMap(repo.objects, parseCommit(commit.data).tree);
        if (path === '') {
          // root listing
          const seen = new Map<string, { type: string; name: string; path: string; sha: string }>();
          for (const p of files.keys()) {
            const top = p.split('/')[0]!;
            if (seen.has(top)) continue;
            if (p.includes('/')) {
              const dirTree = findDirTree(repo, parseCommit(commit.data).tree, top);
              seen.set(top, { type: 'dir', name: top, path: top, sha: dirTree ?? '' });
            } else {
              seen.set(top, { type: 'file', name: top, path: top, sha: files.get(p)!.oid });
            }
          }
          sendJson(res, 200, [...seen.values()].map((e) => ({ ...e, url: '', size: e.type === 'file' ? (repo.objects.get(e.sha)?.data.length ?? 0) : 0 })));
          return true;
        }
        const file = files.get(path);
        if (file) {
          const blob = repo.objects.get(file.oid)!;
          sendJson(res, 200, { type: 'file', encoding: 'base64', size: blob.data.length, name: path.split('/').pop(), path, content: b64encode(blob.data), sha: file.oid, url: '' });
          return true;
        }
        // directory?
        const prefix = `${path}/`;
        const entries: Record<string, unknown>[] = [];
        const seenDirs = new Set<string>();
        for (const [p, entry] of files) {
          if (!p.startsWith(prefix)) continue;
          const restPath = p.slice(prefix.length);
          const firstSeg = restPath.split('/')[0]!;
          if (restPath.includes('/')) {
            if (seenDirs.has(firstSeg)) continue;
            seenDirs.add(firstSeg);
            const dirTree = findDirTree(repo, parseCommit(commit.data).tree, `${path}/${firstSeg}`);
            entries.push({ type: 'dir', name: firstSeg, path: `${path}/${firstSeg}`, sha: dirTree ?? '', size: 0, url: '' });
          } else {
            entries.push({ type: 'file', name: firstSeg, path: p, sha: entry.oid, size: repo.objects.get(entry.oid)?.data.length ?? 0, url: '' });
          }
        }
        if (entries.length === 0) { errJson(res, 404, 'Not Found'); return true; }
        entries.sort((a, b) => String(a.name).localeCompare(String(b.name)));
        sendJson(res, 200, entries);
        return true;
      }
      if (method === 'PUT') {
        const parsed = parseJsonBody(bodyBuf);
        if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return true; }
        const b = (parsed.value ?? {}) as Record<string, unknown>;
        if (typeof b.message !== 'string' || typeof b.content !== 'string') { errJson(res, 422, 'message and content are required'); return true; }
        const result = putContentFile(repo, path, b.content, b.message, typeof b.branch === 'string' ? b.branch : undefined, typeof b.sha === 'string' ? b.sha : undefined);
        if (result.status === 409) { errJson(res, 409, result.message ?? 'Conflict'); return true; }
        if (result.status === 422) { errJson(res, 422, result.message ?? 'Unprocessable'); return true; }
        sendJson(res, result.status, { content: { name: path.split('/').pop(), path, sha: result.contentSha, size: b64decode(b.content).length, url: '', encoding: 'base64' }, commit: { sha: result.commitSha, message: b.message } });
        return true;
      }
      if (method === 'DELETE') {
        const parsed = parseJsonBody(bodyBuf);
        if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return true; }
        const b = (parsed.value ?? {}) as Record<string, unknown>;
        if (typeof b.message !== 'string') { errJson(res, 422, 'message is required'); return true; }
        const result = deleteContentFile(repo, path, b.message, typeof b.branch === 'string' ? b.branch : undefined, typeof b.sha === 'string' ? b.sha : undefined);
        if (result.status === 404) { errJson(res, 404, 'Not Found'); return true; }
        if (result.status === 409) { errJson(res, 409, result.message ?? 'Conflict'); return true; }
        sendJson(res, 200, { commit: { sha: result.commitSha, message: b.message } });
        return true;
      }
      return false;
    }

    if (sub === 'labels') {
      if (method === 'GET' && rest.length === 1) {
        sendJson(res, 200, [...repo.labels.values()].map(labelJsonOf));
        return true;
      }
      if (method === 'POST' && rest.length === 1) {
        const parsed = parseJsonBody(bodyBuf);
        if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return true; }
        const b = (parsed.value ?? {}) as Record<string, unknown>;
        const name = typeof b.name === 'string' ? b.name : '';
        if (name === '') { errJson(res, 422, 'name is required'); return true; }
        const existing = repo.labels.get(name);
        if (existing) { sendJson(res, 201, labelJsonOf(existing)); return true; }
        const label: Label = { id: nextLabelId++, name, color: typeof b.color === 'string' ? b.color : 'ededed', description: typeof b.description === 'string' ? b.description : '' };
        repo.labels.set(name, label);
        sendJson(res, 201, labelJsonOf(label));
        return true;
      }
      return false;
    }

    if (sub === 'issues') {
      if (rest.length === 1) {
        if (method === 'POST') {
          const parsed = parseJsonBody(bodyBuf);
          if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return true; }
          const b = (parsed.value ?? {}) as Record<string, unknown>;
          if (typeof b.title !== 'string' || b.title === '') { errJson(res, 422, 'title is required'); return true; }
          const labelNames = Array.isArray(b.labels) ? (b.labels as unknown[]).map((x) => (typeof x === 'string' ? x : String((x as Record<string, unknown>).name ?? ''))).filter((x) => x !== '') : [];
          const made = createIssueOn(repo, b.title, typeof b.body === 'string' ? b.body : '', labelNames);
          if (made.error) { errJson(res, 422, made.error); return true; }
          sendJsonText(res, 201, made.issue!.jsonBuf);
          return true;
        }
        if (method === 'GET') {
          const state = query.get('state') ?? 'open';
          const sort = query.get('sort') ?? 'created';
          const direction = query.get('direction') ?? 'desc';
          let list = [...repo.issues];
          if (state === 'open') list = list.filter((i) => i.state === 'open');
          else if (state === 'closed') list = list.filter((i) => i.state === 'closed');
          if (sort === 'created') list.sort((a, b) => (direction === 'asc' ? a.number - b.number : b.number - a.number));
          const { page } = paginate(list, query);
          const link = linkHeader(req, query, list.length);
          sendJson(res, 200, page.map((i) => JSON.parse(i.json) as unknown), link === null ? {} : { link });
          return true;
        }
        return false;
      }
      const num = Number(rest[1]);
      if (!Number.isInteger(num) || num <= 0) return false;
      if (rest.length === 2) {
        if (method === 'GET') {
          const issue = repo.issuesByNumber.get(num);
          if (!issue) { errJson(res, 404, 'Not Found'); return true; }
          sendJsonText(res, 200, issue.jsonBuf);
          return true;
        }
        if (method === 'PATCH') {
          const issue = repo.issuesByNumber.get(num);
          if (!issue) { errJson(res, 404, 'Not Found'); return true; }
          const parsed = parseJsonBody(bodyBuf);
          if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return true; }
          const b = (parsed.value ?? {}) as Record<string, unknown>;
          if (b.state === 'open' || b.state === 'closed') {
            issue.state = b.state;
            issue.closedAt = b.state === 'closed' ? FIXED_ISO : null;
          }
          if (typeof b.title === 'string') issue.title = b.title;
          if (typeof b.body === 'string') issue.body = b.body;
          refreshIssueJson(repo, issue);
          sendJsonText(res, 200, issue.jsonBuf);
          return true;
        }
        return false;
      }
      if (rest[2] === 'comments') {
        const issue = repo.issuesByNumber.get(num);
        if (!issue) { errJson(res, 404, 'Not Found'); return true; }
        if (method === 'POST') {
          const parsed = parseJsonBody(bodyBuf);
          if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return true; }
          const b = (parsed.value ?? {}) as Record<string, unknown>;
          if (typeof b.body !== 'string') { errJson(res, 422, 'body is required'); return true; }
          const comment: IssueComment = { id: repo.nextCommentId++, body: b.body, user: ownerLogin() };
          issue.comments.push(comment);
          refreshIssueJson(repo, issue);
          sendJson(res, 201, { id: comment.id, node_id: globalId('IssueComment', repo.id, issue.number, comment.id), body: comment.body, user: userJson(comment.user), created_at: FIXED_ISO, updated_at: FIXED_ISO, html_url: '' });
          return true;
        }
        if (method === 'GET') {
          sendJson(res, 200, issue.comments.map((c) => ({ id: c.id, node_id: globalId('IssueComment', repo.id, issue.number, c.id), body: c.body, user: userJson(c.user), created_at: FIXED_ISO, updated_at: FIXED_ISO, html_url: '' })));
          return true;
        }
        return false;
      }
      return false;
    }

    if (sub === 'pulls') {
      if (rest.length === 1) {
        if (method === 'POST') {
          const parsed = parseJsonBody(bodyBuf);
          if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return true; }
          const b = (parsed.value ?? {}) as Record<string, unknown>;
          const head = typeof b.head === 'string' ? b.head : '';
          const base = typeof b.base === 'string' ? b.base : '';
          const title = typeof b.title === 'string' ? b.title : '';
          const headSha = repo.refs.get(`refs/heads/${head}`);
          const baseSha = repo.refs.get(`refs/heads/${base}`);
          if (!headSha || !baseSha || head === '' || base === '' || head === base || title === '') { errJson(res, 422, 'Invalid head or base'); return true; }
          const number = repo.nextNumber++;
          const pr: PullRequest = {
            id: nextGlobalId++, number, title, body: typeof b.body === 'string' ? b.body : '', state: 'open', merged: false, mergedAt: null, mergeCommitSha: null,
            headRef: head, baseRef: base, headSha, baseSha, user: ownerLogin(), createdAt: FIXED_ISO, updatedAt: FIXED_ISO, json: '', jsonBuf: EMPTY_BODY,
          };
          repo.pulls.push(pr);
          repo.pullsByNumber.set(number, pr);
          refreshPullJson(repo, pr);
          sendJsonText(res, 201, pr.jsonBuf);
          return true;
        }
        if (method === 'GET') {
          const state = query.get('state') ?? 'open';
          let list = [...repo.pulls];
          if (state === 'open') list = list.filter((p) => p.state === 'open');
          else if (state === 'closed') list = list.filter((p) => p.state === 'closed');
          list.sort((a, b) => b.number - a.number);
          const { page } = paginate(list, query);
          const link = linkHeader(req, query, list.length);
          sendJson(res, 200, page.map((p) => JSON.parse(p.json) as unknown), link === null ? {} : { link });
          return true;
        }
        return false;
      }
      const num = Number(rest[1]);
      if (!Number.isInteger(num) || num <= 0) return false;
      if (rest.length === 2 && method === 'GET') {
        const pr = repo.pullsByNumber.get(num);
        if (!pr) { errJson(res, 404, 'Not Found'); return true; }
        sendJsonText(res, 200, pr.jsonBuf);
        return true;
      }
      if (rest.length === 3 && rest[2] === 'files' && method === 'GET') {
        const pr = repo.pullsByNumber.get(num);
        if (!pr) { errJson(res, 404, 'Not Found'); return true; }
        const base = mergeBase(repo.objects, pr.headSha, pr.baseSha) ?? pr.baseSha;
        const files = diffFiles(repo, base, pr.headSha);
        sendJson(res, 200, files.map((f) => ({ sha: '', filename: f.filename, status: f.status, additions: f.additions, deletions: f.deletions, changes: f.changes, blob_url: '', raw_url: '', contents_url: '' })));
        return true;
      }
      if (rest.length === 3 && rest[2] === 'merge' && method === 'PUT') {
        const pr = repo.pullsByNumber.get(num);
        if (!pr) { errJson(res, 404, 'Not Found'); return true; }
        if (pr.merged || pr.state === 'closed') { errJson(res, 405, 'Pull request has already been merged'); return true; }
        const merged = squashMerge(repo, pr);
        if (merged === null) { errJson(res, 405, 'Merge conflict'); return true; }
        sendJson(res, 200, { sha: merged, merged: true, message: `Pull request #${num} merged` });
        return true;
      }
      return false;
    }

    return false;
  }

  return false;
}

/** Find a directory's tree oid by walking a root tree. */
function findDirTree(repo: Repo, rootTreeOid: string, dirPath: string): string | null {
  let cur = rootTreeOid;
  for (const seg of dirPath.split('/')) {
    const obj = repo.objects.get(cur);
    if (!obj || obj.type !== 'tree') return null;
    const entry = parseTree(obj.data).find((e) => e.name === seg && e.mode === '40000');
    if (!entry) return null;
    cur = entry.oid;
  }
  return cur;
}

// ---------------------------------------------------------------------------
// git smart HTTP
// ---------------------------------------------------------------------------

function sortedRefNames(repo: Repo): string[] {
  return [...repo.refs.keys()].sort();
}

function v0Capabilities(service: 'git-upload-pack' | 'git-receive-pack'): string {
  if (service === 'git-receive-pack') {
    return 'report-status side-band-64k delete-refs ofs-delta agent=forge/1.0 object-format=sha1';
  }
  return 'multi_ack thin-pack side-band side-band-64k ofs-delta shallow deepen-since deepen-not no-progress include-tag multi_ack_detailed allow-tip-sha1-in-want allow-reachable-sha1-in-want no-done symref=HEAD:refs/heads/main agent=forge/1.0 object-format=sha1';
}

function buildV0Advertisement(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const parts: Buffer[] = [pktLine(`# service=${service}\n`), PKT_FLUSH];
  const caps = v0Capabilities(service);
  const refs = sortedRefNames(repo);
  const defaultBranch = repo.defaultBranch;
  if (refs.length === 0) {
    parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    const headTip = repo.refs.get(`refs/heads/${defaultBranch}`);
    let first = true;
    if (headTip) {
      parts.push(pktLine(`${headTip} HEAD\0${caps}\n`));
      first = false;
    }
    for (const ref of refs) {
      const oid = repo.refs.get(ref)!;
      const line = first ? `${oid} ${ref}\0${caps}\n` : `${oid} ${ref}\n`;
      parts.push(pktLine(line));
      first = false;
      const obj = repo.objects.get(oid);
      if (obj && obj.type === 'tag') {
        const peeled = peelToCommit(repo.objects, oid);
        parts.push(pktLine(`${peeled} ${ref}^{}\n`));
      }
    }
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

function buildV2Advertisement(): Buffer {
  return Buffer.concat([
    pktLine('version 2\n'),
    pktLine('agent=forge/1.0\n'),
    pktLine('ls-refs=unborn\n'),
    pktLine('fetch=shallow filter\n'),
    pktLine('object-format=sha1\n'),
    pktLine('object-info\n'),
    PKT_FLUSH,
  ]);
}

/** The v2 capability advertisement never varies: build it once, reuse it for every clone/fetch. */
const AD_V2 = buildV2Advertisement();

interface FetchPlan {
  pack: Buffer;
  shallow: string[];
  unshallow: string[];
  acks: string[];
}

function computeFetch(repo: Repo, wants: string[], haves: string[], shallowGiven: string[], depth: number | null): FetchPlan {
  const cacheKey = NOCACHE ? '' : `${repo.version}:${wants.join(',')}:${haves.join(',')}:${shallowGiven.join(',')}:${depth ?? ''}`;
  if (!NOCACHE && cacheKey !== '') {
    const hit = repo.packCache.get(cacheKey);
    if (hit) {
      // pack cached; shallow/unshallow/acks recomputed cheaply from the same plan is not
      // stored, so cache the full plan under a parallel key.
      const planHit = (repo as unknown as { _planCache?: Map<string, FetchPlan> })._planCache?.get(cacheKey);
      if (planHit) return planHit;
    }
  }
  const acks: string[] = [];
  for (const h of haves) if (repo.objects.has(h)) acks.push(h);
  // Commit layers from the wants (peeling tags to their commits for depth).
  const wantCommits: string[] = [];
  const extraObjects = new Set<string>(); // tag objects themselves
  for (const w of wants) {
    const obj = repo.objects.get(w);
    if (!obj) continue;
    if (obj.type === 'tag') {
      extraObjects.add(w);
      wantCommits.push(peelToCommit(repo.objects, w));
    } else if (obj.type === 'commit') {
      wantCommits.push(w);
    } else {
      extraObjects.add(w);
    }
  }
  const layers: string[][] = [];
  const seenCommits = new Set<string>();
  let frontier = [...new Set(wantCommits)];
  while (frontier.length > 0 && (depth === null || layers.length < depth)) {
    layers.push(frontier);
    for (const c of frontier) seenCommits.add(c);
    const next: string[] = [];
    for (const c of frontier) {
      const obj = repo.objects.get(c);
      if (!obj || obj.type !== 'commit') continue;
      for (const p of parseCommit(obj.data).parents) {
        if (!seenCommits.has(p) && !next.includes(p)) next.push(p);
      }
    }
    frontier = next;
  }
  // What the client already holds. In shallow negotiation (shallowGiven non-empty)
  // the client holds only the boundary commits + their tree closures, never the
  // ancestors behind the boundary; treating haves as full history there would
  // wrongly suppress the parents a deepen is asking for. In full-history mode
  // haves are commits the client holds with all their ancestors.
  const held = new Set<string>();
  const addBoundaryClosure = (oid: string): void => {
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') return;
    held.add(oid);
    for (const x of collectReachable(repo.objects, [parseCommit(obj.data).tree])) held.add(x);
  };
  if (shallowGiven.length > 0) {
    for (const h of haves) addBoundaryClosure(h);
    for (const s of shallowGiven) addBoundaryClosure(s);
  } else if (haves.length > 0) {
    for (const oid of collectReachable(repo.objects, haves)) held.add(oid);
  }
  const send = new Set<string>();
  for (const o of extraObjects) if (!held.has(o)) send.add(o);
  if (depth === null) {
    for (const oid of collectReachable(repo.objects, wantCommits)) {
      if (!held.has(oid)) send.add(oid);
    }
  } else {
    for (const layer of layers) {
      for (const c of layer) {
        if (held.has(c)) continue;
        send.add(c);
        const obj = repo.objects.get(c);
        if (!obj || obj.type !== 'commit') continue;
        for (const oid of collectReachable(repo.objects, [parseCommit(obj.data).tree])) {
          if (!held.has(oid)) send.add(oid);
        }
      }
    }
  }
  const sorted = [...send].sort();
  const packObjects: GitObj[] = [];
  for (const oid of sorted) {
    const obj = repo.objects.get(oid);
    if (obj) packObjects.push(obj);
  }
  const pack = writePack(packObjects);
  let shallow: string[] = [];
  let unshallow: string[] = [];
  if (depth !== null) {
    shallow = layers.length > 0 ? layers[layers.length - 1]! : [];
    const newBoundary = new Set(shallow);
    unshallow = shallowGiven.filter((s) => !newBoundary.has(s));
  } else {
    unshallow = [...shallowGiven];
  }
  const plan: FetchPlan = { pack, shallow, unshallow, acks };
  if (!NOCACHE && cacheKey !== '') {
    const holder = repo as unknown as { _planCache?: Map<string, FetchPlan> };
    if (!holder._planCache) holder._planCache = new Map();
    if (holder._planCache.size > 64) holder._planCache.clear();
    holder._planCache.set(cacheKey, plan);
    repo.packCache.set(cacheKey, pack);
  }
  return plan;
}

function sidebandPackets(pack: Buffer): Buffer[] {
  const out: Buffer[] = [];
  const CHUNK = 32768;
  for (let off = 0; off < pack.length; off += CHUNK) {
    const piece = pack.subarray(off, Math.min(pack.length, off + CHUNK));
    out.push(band1PktLine(piece));
  }
  return out;
}

function handleLsRefs(repo: Repo, bodyBuf: Buffer): Buffer {
  const packets = parsePktLines(bodyBuf);
  let peel = false;
  let symrefs = false;
  let unborn = false;
  const prefixes: string[] = [];
  let afterDelim = false;
  for (const p of packets) {
    if (p.kind === 'delim') { afterDelim = true; continue; }
    if (p.kind === 'flush') break;
    if (!afterDelim) continue;
    const line = p.payload.toString('utf8').replace(/\n$/, '');
    if (line === 'peel') peel = true;
    else if (line === 'symrefs') symrefs = true;
    else if (line === 'unborn') unborn = true;
    else if (line.startsWith('ref-prefix ')) prefixes.push(line.slice('ref-prefix '.length));
  }
  const cacheKey = NOCACHE ? '' : `${repo.version}:peel=${peel}:sym=${symrefs}:unb=${unborn}:${prefixes.join(',')}`;
  if (!NOCACHE && cacheKey !== '' && repo.lsCache.has(cacheKey)) return repo.lsCache.get(cacheKey)!;
  const lines: Buffer[] = [];
  const keep = (name: string): boolean => prefixes.length === 0 || prefixes.some((pre) => name.startsWith(pre));
  const headTip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
  if (headTip) {
    if (keep('HEAD')) {
      lines.push(pktLine(`${headTip} HEAD${symrefs ? ` symref-target:refs/heads/${repo.defaultBranch}` : ''}\n`));
    }
  } else if (unborn) {
    lines.push(pktLine(`unborn HEAD${symrefs ? ` symref-target:refs/heads/${repo.defaultBranch}` : ''}\n`));
  }
  for (const ref of sortedRefNames(repo)) {
    if (!keep(ref)) continue;
    const oid = repo.refs.get(ref)!;
    let suffix = '';
    const obj = repo.objects.get(oid);
    if (peel && obj && obj.type === 'tag') suffix += ` peeled:${peelToCommit(repo.objects, oid)}`;
    lines.push(pktLine(`${oid} ${ref}${suffix}\n`));
  }
  lines.push(PKT_FLUSH);
  const out = Buffer.concat(lines);
  if (!NOCACHE && cacheKey !== '') {
    if (repo.lsCache.size > 32) repo.lsCache.clear();
    repo.lsCache.set(cacheKey, out);
  }
  return out;
}

function handleFetchV2(repo: Repo, bodyBuf: Buffer, preParsed?: Pkt[]): Buffer {
  const packets = preParsed ?? parsePktLines(bodyBuf);
  const wants: string[] = [];
  const haves: string[] = [];
  const shallowGiven: string[] = [];
  let depth: number | null = null;
  let afterDelim = false;
  for (const p of packets) {
    if (p.kind === 'delim') { afterDelim = true; continue; }
    if (p.kind === 'flush') break;
    if (!afterDelim) continue;
    const line = p.payload.toString('utf8').replace(/\n$/, '');
    if (line.startsWith('want ')) wants.push(line.slice(5).trim());
    else if (line.startsWith('have ')) haves.push(line.slice(5).trim());
    else if (line.startsWith('shallow ')) shallowGiven.push(line.slice(8).trim());
    else if (line.startsWith('deepen ')) {
      const n = parseInt(line.slice(7), 10);
      if (Number.isFinite(n) && n > 0) depth = n;
    }
  }
  const plan = computeFetch(repo, wants, haves, shallowGiven, depth);
  // Real git (and the protocol-v2 text) only expects the acknowledgments section
  // when the client sent haves; with no haves the first section must be the
  // packfile (or shallow-info). The kit client accepts either order.
  const parts: Buffer[] = [];
  if (haves.length > 0) {
    parts.push(pktLine('acknowledgments\n'));
    if (plan.acks.length > 0) {
      for (const a of plan.acks) parts.push(pktLine(`ACK ${a}\n`));
      parts.push(pktLine('ready\n'));
    } else {
      parts.push(pktLine('NAK\n'));
    }
    parts.push(PKT_DELIM);
  }
  if (plan.shallow.length > 0 || plan.unshallow.length > 0) {
    parts.push(pktLine('shallow-info\n'));
    for (const s of plan.shallow) parts.push(pktLine(`shallow ${s}\n`));
    for (const s of plan.unshallow) parts.push(pktLine(`unshallow ${s}\n`));
    parts.push(PKT_DELIM);
  }
  parts.push(pktLine('packfile\n'));
  parts.push(...sidebandPackets(plan.pack));
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

function handleFetchV0(repo: Repo, bodyBuf: Buffer): Buffer {
  const packets = parsePktLines(bodyBuf);
  const wants: string[] = [];
  const haves: string[] = [];
  const shallowGiven: string[] = [];
  let depth: number | null = null;
  let section = 0;
  for (const p of packets) {
    if (p.kind === 'flush') { section += 1; continue; }
    if (p.kind !== 'data') continue;
    const line = p.payload.toString('utf8').replace(/\n$/, '');
    if (section === 0) {
      if (line.startsWith('want ')) wants.push(line.slice(5).split(' ')[0]!);
      else if (line.startsWith('shallow ')) shallowGiven.push(line.slice(8).trim());
      else if (line.startsWith('deepen ')) {
        const n = parseInt(line.slice(7), 10);
        if (Number.isFinite(n) && n > 0) depth = n;
      }
    } else {
      if (line.startsWith('have ')) haves.push(line.slice(5).trim());
    }
  }
  const plan = computeFetch(repo, wants, haves, shallowGiven, depth);
  const parts: Buffer[] = [];
  if (plan.acks.length > 0) {
    for (const a of plan.acks) parts.push(pktLine(`ACK ${a}\n`));
  } else {
    parts.push(pktLine('NAK\n'));
  }
  for (const s of plan.shallow) parts.push(pktLine(`shallow ${s}\n`));
  for (const s of plan.unshallow) parts.push(pktLine(`unshallow ${s}\n`));
  parts.push(...sidebandPackets(plan.pack));
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

interface PushCommand {
  oldOid: string;
  newOid: string;
  ref: string;
}

function handleReceivePack(repo: Repo, bodyBuf: Buffer): Buffer {
  const commands: PushCommand[] = [];
  let packStart = 0;
  let off = 0;
  // Re-walk the raw buffer: commands are pkt-lines until the first flush; the rest is the pack.
  while (off + 4 <= bodyBuf.length) {
    const head = bodyBuf.subarray(off, off + 4).toString('ascii');
    if (head === '0000') { off += 4; packStart = off; break; }
    const len = parseInt(head, 16);
    if (!Number.isFinite(len) || len < 4 || off + len > bodyBuf.length) { packStart = bodyBuf.length; break; }
    const payload = bodyBuf.subarray(off + 4, off + len).toString('utf8');
    const nul = payload.indexOf('\0');
    const text = (nul >= 0 ? payload.slice(0, nul) : payload).replace(/\n$/, '');
    const parts = text.split(' ');
    if (parts.length >= 3) commands.push({ oldOid: parts[0]!, newOid: parts[1]!, ref: parts.slice(2).join(' ') });
    off += len;
  }
  if (packStart === 0) packStart = bodyBuf.length;
  const packBytes = bodyBuf.subarray(packStart);
  let unpackOk = true;
  let unpackDetail = 'ok';
  if (packBytes.length > 0) {
    try {
      const objects = readPack(packBytes, (oid) => repo.objects.get(oid));
      for (const [oid, obj] of objects) {
        if (!repo.objects.has(oid)) repo.objects.set(oid, obj);
      }
    } catch (err) {
      unpackOk = false;
      unpackDetail = err instanceof Error ? err.message : 'unpack error';
    }
  }
  const reportLines: string[] = [];
  let changed = false;
  for (const cmd of commands) {
    if (!cmd.ref.startsWith('refs/')) {
      reportLines.push(`ng ${cmd.ref} invalid ref`);
      continue;
    }
    const current = repo.refs.get(cmd.ref);
    if (!unpackOk) {
      reportLines.push(`ng ${cmd.ref} unpack failed`);
      continue;
    }
    if (cmd.newOid === ZERO_OID) {
      // delete
      if (current === undefined) {
        reportLines.push(`ng ${cmd.ref} no such ref`);
      } else if (cmd.oldOid !== ZERO_OID && cmd.oldOid !== current) {
        reportLines.push(`ng ${cmd.ref} stale info`);
      } else {
        repo.refs.delete(cmd.ref);
        changed = true;
        reportLines.push(`ok ${cmd.ref}`);
      }
      continue;
    }
    if (!repo.objects.has(cmd.newOid)) {
      reportLines.push(`ng ${cmd.ref} missing object`);
      continue;
    }
    if (cmd.oldOid === ZERO_OID) {
      if (current !== undefined) {
        reportLines.push(`ng ${cmd.ref} already exists`);
      } else {
        repo.refs.set(cmd.ref, cmd.newOid);
        changed = true;
        reportLines.push(`ok ${cmd.ref}`);
      }
      continue;
    }
    if (current === undefined) {
      reportLines.push(`ng ${cmd.ref} no such ref`);
      continue;
    }
    if (cmd.oldOid !== current) {
      reportLines.push(`ng ${cmd.ref} stale info`);
      continue;
    }
    if (cmd.ref.startsWith('refs/tags/')) {
      reportLines.push(`ng ${cmd.ref} already exists`);
      continue;
    }
    if (cmd.newOid === current) {
      reportLines.push(`ok ${cmd.ref}`);
      continue;
    }
    if (!isAncestor(repo.objects, current, cmd.newOid)) {
      reportLines.push(`ng ${cmd.ref} non-fast-forward`);
      continue;
    }
    repo.refs.set(cmd.ref, cmd.newOid);
    changed = true;
    reportLines.push(`ok ${cmd.ref}`);
  }
  if (changed) bump(repo);
  // The report-status stream is itself pkt-framed inside band 1, including its
  // own terminating flush packet; the outer flush then ends the sideband stream.
  // Real git's packet reader needs the inner flush, or it dies with
  // "the remote end hung up unexpectedly". Each band-1 payload is itself a
  // pkt-line (header included), not the raw text: the client strips the band
  // byte and parses pkt-lines from what is left.
  const outer: Buffer[] = [band1PktLine(pktLine(`unpack ${unpackOk ? 'ok' : unpackDetail}\n`))];
  for (const line of reportLines) outer.push(band1PktLine(pktLine(`${line}\n`)));
  outer.push(band1PktLine(PKT_FLUSH));
  outer.push(PKT_FLUSH);
  return Buffer.concat(outer);
}

async function handleGit(req: IncomingMessage, res: ServerResponse, owner: string, repoName: string, segs: string[], query: URLSearchParams, bodyBuf: Buffer): Promise<boolean> {
  const method = req.method ?? 'GET';
  if (!repoRouteOwner(owner)) { errJson(res, 404, 'Not Found'); return true; }
  const repo = findRepo(repoName);
  if (segs[0] === 'info' && segs[1] === 'refs' && method === 'GET') {
    if (!repo) { errJson(res, 404, 'Not Found'); return true; }
    const service = query.get('service') ?? '';
    if (service === 'git-upload-pack') {
      const v2 = (req.headers['git-protocol'] ?? '') === 'version=2';
      if (v2) {
        sendRaw(res, 200, 'application/x-git-upload-pack-advertisement', AD_V2);
      } else {
        if (NOCACHE || repo.adV0 === null) repo.adV0 = buildV0Advertisement(repo, 'git-upload-pack');
        sendRaw(res, 200, 'application/x-git-upload-pack-advertisement', repo.adV0);
      }
      return true;
    }
    if (service === 'git-receive-pack') {
      if (NOCACHE || repo.adRecv === null) repo.adRecv = buildV0Advertisement(repo, 'git-receive-pack');
      sendRaw(res, 200, 'application/x-git-receive-pack-advertisement', repo.adRecv);
      return true;
    }
    errJson(res, 400, 'Invalid service');
    return true;
  }
  if (!repo) { errJson(res, 404, 'Not Found'); return true; }
  if (segs[0] === 'git-upload-pack' && method === 'POST') {
    const v2 = (req.headers['git-protocol'] ?? '') === 'version=2';
    try {
      // Distinguish ls-refs from fetch for v2 by the first command line, before
      // paying for a fetch plan the ls-refs answer throws away.
      if (v2) {
        const packets = parsePktLines(bodyBuf);
        const first = packets.find((p) => p.kind === 'data');
        const cmd = first?.payload.toString('utf8').replace(/\n$/, '') ?? '';
        if (cmd.startsWith('command=ls-refs')) {
          sendRaw(res, 200, 'application/x-git-upload-pack-result', handleLsRefs(repo, bodyBuf));
          return true;
        }
        sendRaw(res, 200, 'application/x-git-upload-pack-result', handleFetchV2(repo, bodyBuf, packets));
        return true;
      }
      sendRaw(res, 200, 'application/x-git-upload-pack-result', handleFetchV0(repo, bodyBuf));
    } catch {
      errJson(res, 400, 'Bad Request');
    }
    return true;
  }
  if (segs[0] === 'git-receive-pack' && method === 'POST') {
    try {
      const out = handleReceivePack(repo, bodyBuf);
      sendRaw(res, 200, 'application/x-git-receive-pack-result', out);
    } catch {
      errJson(res, 400, 'Bad Request');
    }
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// GraphQL
// ---------------------------------------------------------------------------

interface GQLTok { kind: 'punct' | 'name' | 'string' | 'int' | 'float'; value: string }

function tokenizeGQL(src: string): GQLTok[] {
  const toks: GQLTok[] = [];
  let i = 0;
  while (i < src.length) {
    const ch = src[i]!;
    if (/\s/.test(ch) || ch === ',') { i++; continue; }
    if (ch === '#') { while (i < src.length && src[i] !== '\n') i++; continue; }
    if (ch === '.' && src.slice(i, i + 3) === '...') { toks.push({ kind: 'punct', value: '...' }); i += 3; continue; }
    if ('{}():![]=@$'.includes(ch)) { toks.push({ kind: 'punct', value: ch }); i++; continue; }
    if (ch === '"') {
      if (src.slice(i, i + 3) === '"""') {
        const end = src.indexOf('"""', i + 3);
        toks.push({ kind: 'string', value: '' });
        i = end === -1 ? src.length : end + 3;
        continue;
      }
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) {
          const e = src[j + 1]!;
          out += e === 'n' ? '\n' : e === 't' ? '\t' : e === 'r' ? '\r' : e;
          j += 2;
        } else { out += src[j]; j++; }
      }
      toks.push({ kind: 'string', value: out });
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(ch) && (ch !== '-' || /[0-9]/.test(src[i + 1] ?? ''))) {
      let j = i;
      while (j < src.length && /[0-9.eE+-]/.test(src[j]!)) j++;
      const raw = src.slice(i, j);
      toks.push({ kind: /[.eE]/.test(raw) ? 'float' : 'int', value: raw });
      i = j;
      continue;
    }
    if (/[_A-Za-z]/.test(ch)) {
      let j = i;
      while (j < src.length && /[_A-Za-z0-9]/.test(src[j]!)) j++;
      toks.push({ kind: 'name', value: src.slice(i, j) });
      i = j;
      continue;
    }
    i++;
  }
  return toks;
}

interface GQLField {
  name: string;
  alias?: string;
  args: Record<string, unknown>;
  fields: GQLField[];
  spread?: string;
  inlineType?: string;
}
interface GQLOp {
  kind: 'query' | 'mutation';
  varDefs: Record<string, { defaultVal?: unknown }>;
  fields: GQLField[];
}
interface GQLFragment { type: string; fields: GQLField[] }

class GQLParser {
  toks: GQLTok[];
  pos = 0;
  constructor(src: string) { this.toks = tokenizeGQL(src); }
  peek(): GQLTok | undefined { return this.toks[this.pos]; }
  next(): GQLTok | undefined { return this.toks[this.pos++]; }
  expect(value: string): GQLTok {
    const t = this.next();
    if (!t || t.value !== value) throw new Error(`Expected ${value}`);
    return t;
  }
  parseDocument(): { ops: GQLOp[]; frags: Map<string, GQLFragment> } {
    const ops: GQLOp[] = [];
    const frags = new Map<string, GQLFragment>();
    while (this.pos < this.toks.length) {
      const t = this.peek();
      if (!t) break;
      if (t.value === '{') {
        ops.push({ kind: 'query', varDefs: {}, fields: this.parseSelectionSet() });
      } else if (t.value === 'query' || t.value === 'mutation') {
        this.next();
        const kind = t.value as 'query' | 'mutation';
        const nt = this.peek();
        if (nt && nt.kind === 'name') this.next();
        const varDefs = this.parseVarDefs();
        ops.push({ kind, varDefs, fields: this.parseSelectionSet() });
      } else if (t.value === 'fragment') {
        this.next();
        const name = this.next()?.value ?? '';
        this.expect('on');
        const type = this.next()?.value ?? '';
        frags.set(name, { type, fields: this.parseSelectionSet() });
      } else if (t.value === 'subscription') {
        this.next();
        const nt = this.peek();
        if (nt && nt.kind === 'name') this.next();
        this.parseVarDefs();
        this.parseSelectionSet();
      } else {
        this.next();
      }
    }
    return { ops, frags };
  }
  parseVarDefs(): Record<string, { defaultVal?: unknown }> {
    const defs: Record<string, { defaultVal?: unknown }> = {};
    const t = this.peek();
    if (!t || t.value !== '(') return defs;
    this.next();
    while (this.pos < this.toks.length) {
      const tok = this.next();
      if (!tok) break;
      if (tok.value === ')') break;
      if (tok.value === '$') {
        const name = this.next()?.value ?? '';
        this.expect(':');
        // consume type tokens: name, [, ], !
        while (this.pos < this.toks.length) {
          const tt = this.peek()!;
          if (tt.value === '[' || tt.value === ']' || tt.value === '!' || tt.kind === 'name') { this.next(); continue; }
          break;
        }
        const eq = this.peek();
        if (eq && eq.value === '=') {
          this.next();
          defs[name] = { defaultVal: this.parseValue() };
        } else {
          defs[name] = {};
        }
      }
    }
    return defs;
  }
  parseSelectionSet(): GQLField[] {
    this.expect('{');
    const fields: GQLField[] = [];
    while (this.pos < this.toks.length) {
      const t = this.peek();
      if (!t) break;
      if (t.value === '}') { this.next(); break; }
      if (t.value === '...') {
        this.next();
        const nt = this.peek();
        if (nt && nt.value === 'on') {
          this.next();
          const type = this.next()?.value ?? '';
          const sub = this.parseSelectionSet();
          fields.push({ name: '', args: {}, fields: sub, inlineType: type });
        } else if (nt && nt.kind === 'name') {
          const name = this.next()!.value;
          // skip directives
          this.skipDirectives();
          fields.push({ name: '', args: {}, fields: [], spread: name });
        } else {
          this.parseSelectionSet();
        }
        continue;
      }
      if (t.kind !== 'name') { this.next(); continue; }
      const first = this.next()!.value;
      let name = first;
      let alias: string | undefined;
      if (this.peek()?.value === ':') {
        this.next();
        alias = first;
        name = this.next()?.value ?? '';
      }
      let args: Record<string, unknown> = {};
      if (this.peek()?.value === '(') args = this.parseArgs();
      this.skipDirectives();
      let sub: GQLField[] = [];
      if (this.peek()?.value === '{') sub = this.parseSelectionSet();
      fields.push({ name, alias, args, fields: sub });
    }
    return fields;
  }
  skipDirectives(): void {
    while (this.peek()?.value === '@') {
      this.next();
      const nt = this.peek();
      if (nt && nt.kind === 'name') this.next();
      if (this.peek()?.value === '(') this.parseArgs();
    }
  }
  parseArgs(): Record<string, unknown> {
    this.expect('(');
    const args: Record<string, unknown> = {};
    while (this.pos < this.toks.length) {
      const t = this.peek();
      if (!t) break;
      if (t.value === ')') { this.next(); break; }
      if (t.kind === 'name') {
        const name = this.next()!.value;
        this.expect(':');
        args[name] = this.parseValue();
      } else {
        this.next();
      }
    }
    return args;
  }
  parseValue(): unknown {
    const t = this.next();
    if (!t) return null;
    if (t.value === '$') return { __var: this.next()?.value ?? '' };
    if (t.value === '[') {
      const list: unknown[] = [];
      while (this.pos < this.toks.length) {
        if (this.peek()?.value === ']') { this.next(); break; }
        list.push(this.parseValue());
      }
      return list;
    }
    if (t.value === '{') {
      const obj: Record<string, unknown> = {};
      while (this.pos < this.toks.length) {
        const nt = this.peek();
        if (!nt) break;
        if (nt.value === '}') { this.next(); break; }
        if (nt.kind === 'name') {
          const key = this.next()!.value;
          this.expect(':');
          obj[key] = this.parseValue();
        } else {
          this.next();
        }
      }
      return obj;
    }
    if (t.kind === 'string') return t.value;
    if (t.kind === 'int' || t.kind === 'float') return Number(t.value);
    if (t.kind === 'name') {
      if (t.value === 'true') return true;
      if (t.value === 'false') return false;
      if (t.value === 'null') return null;
      return t.value; // enum
    }
    return null;
  }
}

type GQLValue = Record<string, unknown> & { __typename?: string };

function resolveGQLValue(v: unknown, vars: Record<string, unknown>): unknown {
  if (v !== null && typeof v === 'object') {
    if (Array.isArray(v)) return v.map((x) => resolveGQLValue(x, vars));
    const rec = v as Record<string, unknown>;
    if (typeof rec.__var === 'string') return vars[rec.__var] ?? null;
    const out: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(rec)) out[k] = resolveGQLValue(val, vars);
    return out;
  }
  return v;
}

class GQLFieldError extends Error {}

function gqlCursor(num: number): string {
  return Buffer.from(`cursor:${num}`).toString('base64');
}
function gqlCursorNum(cursor: unknown): number | null {
  if (typeof cursor !== 'string') return null;
  try {
    const decoded = Buffer.from(cursor, 'base64').toString('utf8');
    const m = /^cursor:(\d+)$/.exec(decoded);
    return m ? Number(m[1]) : null;
  } catch {
    return null;
  }
}

function issueWrapper(repo: Repo, issue: Issue): GQLValue {
  return {
    __typename: 'Issue',
    __repo: repo,
    __issue: issue,
    id: globalId('Issue', repo.id, issue.number),
    databaseId: issue.number,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state === 'open' ? 'OPEN' : 'CLOSED',
    createdAt: issue.createdAt,
    updatedAt: issue.updatedAt,
    url: '',
    author: { __typename: 'User', login: issue.user, id: globalId('User', 0, issue.user), name: issue.user },
  };
}

function pullWrapper(repo: Repo, pr: PullRequest): GQLValue {
  return {
    __typename: 'PullRequest',
    __repo: repo,
    __pr: pr,
    id: globalId('PullRequest', repo.id, pr.number),
    databaseId: pr.number,
    number: pr.number,
    title: pr.title,
    body: pr.body,
    state: pr.merged ? 'MERGED' : pr.state === 'open' ? 'OPEN' : 'CLOSED',
    merged: pr.merged,
    mergedAt: pr.mergedAt,
    mergeCommitSha: pr.mergeCommitSha,
    headRefName: pr.headRef,
    baseRefName: pr.baseRef,
    headRefOid: pr.headSha,
    baseRefOid: pr.baseSha,
    createdAt: pr.createdAt,
    updatedAt: pr.updatedAt,
    url: '',
    author: { __typename: 'User', login: pr.user, id: globalId('User', 0, pr.user), name: pr.user },
  };
}

function repoWrapper(repo: Repo): GQLValue {
  return {
    __typename: 'Repository',
    __repo: repo,
    id: globalId('Repository', repo.id),
    databaseId: repo.id,
    name: repo.name,
    nameWithOwner: `${ownerLogin()}/${repo.name}`,
    owner: { __typename: 'User', login: ownerLogin(), id: globalId('User', 0, ownerLogin()), name: ownerLogin() },
    defaultBranchRef: { __typename: 'Ref', name: repo.defaultBranch },
    viewerPermission: 'ADMIN',
    hasIssuesEnabled: true,
    createdAt: FIXED_ISO,
    updatedAt: FIXED_ISO,
    url: '',
    description: repo.description,
    isPrivate: repo.private,
  };
}

function paginateGQL<T extends { number: number }>(items: T[], args: Record<string, unknown>, desc: boolean): { nodes: T[]; pageInfo: GQLValue; totalCount: number } {
  const sorted = [...items].sort((a, b) => (desc ? b.number - a.number : a.number - b.number));
  const afterNum = gqlCursorNum(args.after);
  let start = 0;
  if (afterNum !== null) {
    const idx = sorted.findIndex((i) => i.number === afterNum);
    start = idx >= 0 ? idx + 1 : 0;
  }
  const first = typeof args.first === 'number' ? args.first : 30;
  const slice = sorted.slice(start, start + first);
  const hasNext = start + slice.length < sorted.length;
  const endCursor = slice.length > 0 ? gqlCursor(slice[slice.length - 1]!.number) : null;
  return {
    nodes: slice,
    pageInfo: { __typename: 'PageInfo', hasNextPage: hasNext, hasPreviousPage: start > 0, startCursor: slice.length > 0 ? gqlCursor(slice[0]!.number) : null, endCursor },
    totalCount: sorted.length,
  };
}

const GQL_TYPE_FIELDS: Record<string, string[]> = {
  Issue: ['id', 'databaseId', 'number', 'title', 'state', 'body', 'createdAt', 'updatedAt', 'author', 'labels', 'comments', 'url', 'repository'],
  PullRequest: ['id', 'databaseId', 'number', 'title', 'state', 'body', 'merged', 'mergedAt', 'mergeCommitSha', 'headRefName', 'baseRefName', 'mergeable', 'files', 'author', 'createdAt', 'updatedAt', 'url', 'repository', 'headRefOid', 'baseRefOid'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequest', 'pullRequests', 'createdAt', 'updatedAt', 'url', 'description', 'isPrivate'],
  User: ['id', 'login', 'name'],
  Label: ['id', 'name', 'color', 'description'],
  IssueComment: ['id', 'body', 'author', 'createdAt', 'updatedAt'],
  Ref: ['name'],
  IssueConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PageInfo: ['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor'],
  SearchType: [],
};

function resolveGQLField(typeName: string, obj: GQLValue, field: GQLField, args: Record<string, unknown>, ctx: { errors: { message: string }[] }): unknown {
  const name = field.name;
  // Introspection pseudo-fields
  if (typeName === 'Query' && name === '__type') {
    const typeArg = String(args.name ?? '');
    if (typeArg === 'SearchType') {
      return { __typename: '__Type', name: 'SearchType', kind: 'ENUM', fields: null, enumValues: ['ISSUE', 'PULL_REQUEST', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT'].map((n) => ({ name: n })) };
    }
    if (GQL_TYPE_FIELDS[typeArg]) {
      return { __typename: '__Type', name: typeArg, kind: 'OBJECT', fields: GQL_TYPE_FIELDS[typeArg].map((n) => ({ name: n })), enumValues: null };
    }
    return null;
  }
  if (typeName === 'Query' && name === '__schema') {
    return { __typename: '__Schema', queryType: { name: 'Query' }, mutationType: { name: 'Mutation' }, types: [] };
  }
  if (typeName === 'Query') {
    if (name === 'viewer') {
      return { __typename: 'User', login: ownerLogin(), id: globalId('User', 0, ownerLogin()), name: ownerLogin() };
    }
    if (name === 'repository') {
      const owner = String(args.owner ?? '');
      const repoName = String(args.name ?? '');
      if (learnedOwner !== null && owner !== learnedOwner) return null;
      if (learnedOwner === null) learnOwner(owner);
      const repo = findRepo(repoName);
      return repo ? repoWrapper(repo) : null;
    }
    if (name === 'node') {
      const decoded = decodeGlobalId(String(args.id ?? ''));
      if (!decoded) return null;
      if (decoded.kind === 'Repository') {
        const repo = [...reposByName.values()].find((r) => r.id === decoded.parts[0]);
        return repo ? repoWrapper(repo) : null;
      }
      if (decoded.kind === 'Issue') {
        const repo = [...reposByName.values()].find((r) => r.id === decoded.parts[0]);
        const issue = repo?.issuesByNumber.get(decoded.parts[1] as number);
        return repo && issue ? issueWrapper(repo, issue) : null;
      }
      if (decoded.kind === 'PullRequest') {
        const repo = [...reposByName.values()].find((r) => r.id === decoded.parts[0]);
        const pr = repo?.pullsByNumber.get(decoded.parts[1] as number);
        return repo && pr ? pullWrapper(repo, pr) : null;
      }
      return null;
    }
    throw new GQLFieldError(`Cannot query field "${name}" on type "Query".`);
  }
  if (typeName === 'Mutation') {
    if (name === 'createIssue') {
      const input = (args.input ?? {}) as Record<string, unknown>;
      const decoded = decodeGlobalId(String(input.repositoryId ?? ''));
      if (!decoded || decoded.kind !== 'Repository') throw new GQLFieldError('Invalid repositoryId');
      const repo = [...reposByName.values()].find((r) => r.id === decoded.parts[0]);
      if (!repo) throw new GQLFieldError('Repository not found');
      const made = createIssueOn(repo, String(input.title ?? ''), typeof input.body === 'string' ? input.body : '');
      if (made.error) throw new GQLFieldError(made.error);
      return { __typename: 'CreateIssuePayload', issue: issueWrapper(repo, made.issue!), clientMutationId: (input.clientMutationId as string | undefined) ?? null };
    }
    if (name === 'closeIssue') {
      const input = (args.input ?? {}) as Record<string, unknown>;
      const decoded = decodeGlobalId(String(input.issueId ?? ''));
      if (!decoded || decoded.kind !== 'Issue') throw new GQLFieldError('Invalid issueId');
      const repo = [...reposByName.values()].find((r) => r.id === decoded.parts[0]);
      const issue = repo?.issuesByNumber.get(decoded.parts[1] as number);
      if (!repo || !issue) throw new GQLFieldError('Issue not found');
      issue.state = 'closed';
      issue.closedAt = FIXED_ISO;
      refreshIssueJson(repo, issue);
      return { __typename: 'CloseIssuePayload', issue: issueWrapper(repo, issue), clientMutationId: (input.clientMutationId as string | undefined) ?? null };
    }
    if (name === 'createPullRequest') {
      const input = (args.input ?? {}) as Record<string, unknown>;
      const decoded = decodeGlobalId(String(input.repositoryId ?? ''));
      if (!decoded || decoded.kind !== 'Repository') throw new GQLFieldError('Invalid repositoryId');
      const repo = [...reposByName.values()].find((r) => r.id === decoded.parts[0]);
      if (!repo) throw new GQLFieldError('Repository not found');
      const head = String(input.headRefName ?? '');
      const base = String(input.baseRefName ?? '');
      const headSha = repo.refs.get(`refs/heads/${head}`);
      const baseSha = repo.refs.get(`refs/heads/${base}`);
      if (!headSha || !baseSha) throw new GQLFieldError('Invalid head or base');
      const number = repo.nextNumber++;
      const pr: PullRequest = {
        id: nextGlobalId++, number, title: String(input.title ?? ''), body: typeof input.body === 'string' ? input.body : '',
        state: 'open', merged: false, mergedAt: null, mergeCommitSha: null,
        headRef: head, baseRef: base, headSha, baseSha, user: ownerLogin(), createdAt: FIXED_ISO, updatedAt: FIXED_ISO, json: '', jsonBuf: EMPTY_BODY,
      };
      repo.pulls.push(pr);
      repo.pullsByNumber.set(number, pr);
      refreshPullJson(repo, pr);
      return { __typename: 'CreatePullRequestPayload', pullRequest: pullWrapper(repo, pr), clientMutationId: (input.clientMutationId as string | undefined) ?? null };
    }
    if (name === 'mergePullRequest') {
      const input = (args.input ?? {}) as Record<string, unknown>;
      const decoded = decodeGlobalId(String(input.pullRequestId ?? ''));
      if (!decoded || decoded.kind !== 'PullRequest') throw new GQLFieldError('Invalid pullRequestId');
      const repo = [...reposByName.values()].find((r) => r.id === decoded.parts[0]);
      const pr = repo?.pullsByNumber.get(decoded.parts[1] as number);
      if (!repo || !pr) throw new GQLFieldError('Pull request not found');
      if (pr.merged) throw new GQLFieldError('Pull request already merged');
      const merged = squashMerge(repo, pr);
      if (merged === null) throw new GQLFieldError('Merge conflict');
      return { __typename: 'MergePullRequestPayload', pullRequest: pullWrapper(repo, pr), clientMutationId: (input.clientMutationId as string | undefined) ?? null };
    }
    if (name === 'addComment') {
      const input = (args.input ?? {}) as Record<string, unknown>;
      const decoded = decodeGlobalId(String(input.subjectId ?? ''));
      if (!decoded || decoded.kind !== 'Issue') throw new GQLFieldError('Invalid subjectId');
      const repo = [...reposByName.values()].find((r) => r.id === decoded.parts[0]);
      const issue = repo?.issuesByNumber.get(decoded.parts[1] as number);
      if (!repo || !issue) throw new GQLFieldError('Issue not found');
      const comment: IssueComment = { id: repo.nextCommentId++, body: String(input.body ?? ''), user: ownerLogin() };
      issue.comments.push(comment);
      refreshIssueJson(repo, issue);
      const node: GQLValue = { __typename: 'IssueComment', id: globalId('IssueComment', repo.id, issue.number, comment.id), databaseId: comment.id, body: comment.body, createdAt: FIXED_ISO, updatedAt: FIXED_ISO, author: { __typename: 'User', login: comment.user, id: globalId('User', 0, comment.user), name: comment.user } };
      return { __typename: 'AddCommentPayload', commentEdge: { __typename: 'IssueCommentEdge', node, cursor: gqlCursor(comment.id) }, subject: issueWrapper(repo, issue), clientMutationId: (input.clientMutationId as string | undefined) ?? null };
    }
    throw new GQLFieldError(`Cannot query field "${name}" on type "Mutation".`);
  }
  if (typeName === 'Repository') {
    const repo = obj.__repo as Repo;
    if (name === 'issue') {
      const issue = repo.issuesByNumber.get(Number(args.number));
      return issue ? issueWrapper(repo, issue) : null;
    }
    if (name === 'issues') {
      const states = Array.isArray(args.states) ? (args.states as string[]) : null;
      let list = [...repo.issues];
      if (states) {
        const want = new Set(states.map((s) => String(s).toUpperCase()));
        list = list.filter((i) => want.has(i.state === 'open' ? 'OPEN' : 'CLOSED'));
      }
      const orderBy = (args.orderBy ?? {}) as Record<string, unknown>;
      const dir = String(orderBy.direction ?? 'DESC').toUpperCase();
      const page = paginateGQL(list, args, dir === 'DESC');
      return { __typename: 'IssueConnection', nodes: page.nodes.map((i) => issueWrapper(repo, i)), edges: page.nodes.map((i) => ({ node: issueWrapper(repo, i), cursor: gqlCursor(i.number) })), pageInfo: page.pageInfo, totalCount: page.totalCount };
    }
    if (name === 'pullRequest') {
      const pr = repo.pullsByNumber.get(Number(args.number));
      return pr ? pullWrapper(repo, pr) : null;
    }
    if (name === 'pullRequests') {
      const states = Array.isArray(args.states) ? (args.states as string[]) : null;
      let list = [...repo.pulls];
      if (states) {
        const want = new Set(states.map((s) => String(s).toUpperCase()));
        list = list.filter((p) => want.has(p.merged ? 'MERGED' : p.state === 'open' ? 'OPEN' : 'CLOSED'));
      }
      const orderBy = (args.orderBy ?? {}) as Record<string, unknown>;
      const dir = String(orderBy.direction ?? 'DESC').toUpperCase();
      const page = paginateGQL(list, args, dir === 'DESC');
      return { __typename: 'PullRequestConnection', nodes: page.nodes.map((p) => pullWrapper(repo, p)), edges: page.nodes.map((p) => ({ node: pullWrapper(repo, p), cursor: gqlCursor(p.number) })), pageInfo: page.pageInfo, totalCount: page.totalCount };
    }
    if (name in obj) return obj[name];
    throw new GQLFieldError(`Cannot query field "${name}" on type "Repository".`);
  }
  if (typeName === 'Issue') {
    const issue = obj.__issue as Issue;
    if (name === 'labels') {
      return { __typename: 'LabelConnection', nodes: issue.labels.map((l) => ({ __typename: 'Label', id: globalId('Label', 0, l.name), name: l.name, color: l.color, description: l.description })) };
    }
    if (name === 'comments') {
      const repo = obj.__repo as Repo;
      return { __typename: 'IssueCommentConnection', nodes: issue.comments.map((c) => ({ __typename: 'IssueComment', id: globalId('IssueComment', repo.id, issue.number, c.id), databaseId: c.id, body: c.body, createdAt: FIXED_ISO, updatedAt: FIXED_ISO, author: { __typename: 'User', login: c.user, id: globalId('User', 0, c.user), name: c.user } })) };
    }
    if (name in obj) return obj[name];
    throw new GQLFieldError(`Cannot query field "${name}" on type "Issue".`);
  }
  if (typeName === 'PullRequest') {
    const repo = obj.__repo as Repo;
    const pr = obj.__pr as PullRequest;
    if (name === 'mergeable') {
      return mergeConflict(repo, pr) ? 'CONFLICTING' : 'MERGEABLE';
    }
    if (name === 'files') {
      const base = mergeBase(repo.objects, pr.headSha, pr.baseSha) ?? pr.baseSha;
      const files = diffFiles(repo, base, pr.headSha);
      const first = typeof args.first === 'number' ? args.first : 30;
      const slice = files.slice(0, first);
      return { __typename: 'PullRequestFileConnection', nodes: slice.map((f) => ({ __typename: 'PullRequestChangedFile', path: f.filename, additions: f.additions, deletions: f.deletions, changeType: f.status === 'added' ? 'ADDED' : f.status === 'removed' ? 'REMOVED' : 'MODIFIED' })) };
    }
    if (name in obj) return obj[name];
    throw new GQLFieldError(`Cannot query field "${name}" on type "PullRequest".`);
  }
  if (typeName === '__Type') {
    if (name === 'fields') {
      const fields = obj.fields as { name: string }[] | null;
      return fields;
    }
    if (name === 'enumValues') {
      const vals = obj.enumValues as { name: string }[] | null;
      return vals;
    }
    if (name in obj) return obj[name];
    throw new GQLFieldError(`Cannot query field "${name}" on type "__Type".`);
  }
  if (name in obj) return obj[name];
  throw new GQLFieldError(`Cannot query field "${name}" on type "${typeName}".`);
}

function execGQLFields(typeName: string, obj: GQLValue, fields: GQLField[], vars: Record<string, unknown>, frags: Map<string, GQLFragment>, errors: { message: string }[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const field of fields) {
    if (field.spread) {
      const frag = frags.get(field.spread);
      if (!frag) continue;
      if (frag.type && frag.type !== typeName) continue;
      Object.assign(out, execGQLFields(typeName, obj, frag.fields, vars, frags, errors));
      continue;
    }
    if (field.inlineType) {
      if (field.inlineType !== typeName) continue;
      Object.assign(out, execGQLFields(typeName, obj, field.fields, vars, frags, errors));
      continue;
    }
    const key = field.alias ?? field.name;
    const args = resolveGQLValue(field.args, vars) as Record<string, unknown>;
    let value: unknown;
    try {
      value = resolveGQLField(typeName, obj, field, args, { errors });
    } catch (err) {
      if (err instanceof GQLFieldError) {
        errors.push({ message: err.message });
        out[key] = null;
        continue;
      }
      throw err;
    }
    if (field.fields.length > 0) {
      if (value === null || value === undefined) {
        out[key] = null;
      } else if (Array.isArray(value)) {
        out[key] = value.map((v) => {
          if (v !== null && typeof v === 'object') {
            const vt = (v as GQLValue).__typename ?? typeName;
            return execGQLFields(vt, v as GQLValue, field.fields, vars, frags, errors);
          }
          return v;
        });
      } else if (typeof value === 'object') {
        const vt = (value as GQLValue).__typename ?? typeName;
        out[key] = execGQLFields(vt, value as GQLValue, field.fields, vars, frags, errors);
      } else {
        out[key] = value;
      }
    } else {
      out[key] = value;
    }
  }
  return out;
}

function executeGraphQL(body: unknown): { data: Record<string, unknown> | null; errors?: { message: string }[] } {
  const runOne = (doc: { query?: string; variables?: Record<string, unknown> }): { data: Record<string, unknown> | null; errors?: { message: string }[] } => {
    const query = typeof doc.query === 'string' ? doc.query : '';
    const variables = (doc.variables ?? {}) as Record<string, unknown>;
    const errors: { message: string }[] = [];
    try {
      const { ops, frags } = new GQLParser(query).parseDocument();
      if (ops.length === 0) return { data: null, errors: [{ message: 'No operations found' }] };
      const op = ops[0]!;
      const vars: Record<string, unknown> = {};
      for (const [k, def] of Object.entries(op.varDefs)) {
        if (k in variables) vars[k] = variables[k];
        else if (def.defaultVal !== undefined) vars[k] = resolveGQLValue(def.defaultVal, variables);
        else vars[k] = null;
      }
      for (const [k, v] of Object.entries(variables)) if (!(k in vars)) vars[k] = v;
      const rootType = op.kind === 'mutation' ? 'Mutation' : 'Query';
      const data = execGQLFields(rootType, { __typename: rootType }, op.fields, vars, frags, errors);
      const result: { data: Record<string, unknown> | null; errors?: { message: string }[] } = { data };
      if (errors.length > 0) result.errors = errors;
      return result;
    } catch (err) {
      return { data: null, errors: [{ message: err instanceof Error ? err.message : 'GraphQL error' }] };
    }
  };
  if (Array.isArray(body)) {
    // Batched operations are answered as an array in order (handled by caller).
    return { data: null, errors: [{ message: 'Batch must be handled by caller' }] };
  }
  return runOne(body as { query?: string; variables?: Record<string, unknown> });
}

// ---------------------------------------------------------------------------
// MCP (JSON-RPC 2.0 over streamable HTTP)
// ---------------------------------------------------------------------------

const MCP_TOOLS: Record<string, unknown>[] = [
  { name: 'create_repo', description: 'Create a new repository', inputSchema: { type: 'object', properties: { name: { type: 'string', description: 'Repository name' }, description: { type: 'string', description: 'Repository description' }, private: { type: 'boolean', description: 'Whether the repository is private' } }, required: ['name'] } },
  { name: 'get_repo', description: 'Get a repository by owner and name', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' } }, required: ['owner', 'repo'] } },
  { name: 'create_issue', description: 'Create an issue in a repository', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, title: { type: 'string', description: 'Issue title' }, body: { type: 'string', description: 'Issue body' } }, required: ['owner', 'repo', 'title'] } },
  { name: 'list_issues', description: 'List issues in a repository', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, state: { type: 'string', description: 'Issue state filter: open, closed, or all' } }, required: ['owner', 'repo'] } },
  { name: 'create_pull_request', description: 'Create a pull request', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, title: { type: 'string', description: 'Pull request title' }, head: { type: 'string', description: 'Head branch name' }, base: { type: 'string', description: 'Base branch name' } }, required: ['owner', 'repo', 'title', 'head', 'base'] } },
  { name: 'merge_pull_request', description: 'Merge a pull request', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, pull_number: { type: 'number', description: 'Pull request number' } }, required: ['owner', 'repo', 'pull_number'] } },
];
const MCP_TOOLS_JSON = JSON.stringify({ tools: MCP_TOOLS });

function mcpSplitFullName(args: Record<string, unknown>): void {
  if ((args.owner === undefined || args.repo === undefined) && typeof args.full_name === 'string') {
    const parts = args.full_name.split('/');
    if (parts.length === 2) {
      args.owner = parts[0];
      args.repo = parts[1];
    }
  }
}

function mcpToolResult(text: string, isError = false): Record<string, unknown> {
  return { content: [{ type: 'text', text }], ...(isError ? { isError: true } : {}) };
}

function handleMcpCall(name: string, args: Record<string, unknown>): Record<string, unknown> {
  const norm = name.toLowerCase().replace(/[^a-z0-9]/g, '');
  const required = (fields: string[]): string | null => {
    for (const f of fields) if (args[f] === undefined || args[f] === null || args[f] === '') return f;
    return null;
  };
  if (norm === 'createrepo') {
    const missing = required(['name']);
    if (missing) return mcpToolResult(`Missing required argument: ${missing}`, true);
    const repoName = String(args.name);
    if (reposByName.has(repoName)) return mcpToolResult('Repository already exists', true);
    const repo = newRepo(repoName, args.private === true, typeof args.description === 'string' ? args.description : '');
    return mcpToolResult(JSON.stringify(repoJsonOf(repo)));
  }
  if (norm === 'getrepo') {
    mcpSplitFullName(args);
    const missing = required(['owner', 'repo']);
    if (missing) return mcpToolResult(`Missing required argument: ${missing}`, true);
    const owner = String(args.owner);
    if (!repoRouteOwner(owner)) return mcpToolResult('Not Found', true);
    const repo = findRepo(String(args.repo));
    if (!repo) return mcpToolResult('Not Found', true);
    return mcpToolResult(JSON.stringify(repoJsonOf(repo)));
  }
  if (norm === 'createissue') {
    mcpSplitFullName(args);
    const missing = required(['owner', 'repo', 'title']);
    if (missing) return mcpToolResult(`Missing required argument: ${missing}`, true);
    const owner = String(args.owner);
    if (!repoRouteOwner(owner)) return mcpToolResult('Not Found', true);
    const repo = findRepo(String(args.repo));
    if (!repo) return mcpToolResult('Not Found', true);
    const made = createIssueOn(repo, String(args.title), typeof args.body === 'string' ? args.body : '');
    if (made.error) return mcpToolResult(made.error, true);
    return mcpToolResult(made.issue!.json);
  }
  if (norm === 'listissues') {
    mcpSplitFullName(args);
    const missing = required(['owner', 'repo']);
    if (missing) return mcpToolResult(`Missing required argument: ${missing}`, true);
    const owner = String(args.owner);
    if (!repoRouteOwner(owner)) return mcpToolResult('Not Found', true);
    const repo = findRepo(String(args.repo));
    if (!repo) return mcpToolResult('Not Found', true);
    const state = typeof args.state === 'string' ? args.state : 'open';
    let list = [...repo.issues];
    if (state === 'open') list = list.filter((i) => i.state === 'open');
    else if (state === 'closed') list = list.filter((i) => i.state === 'closed');
    return mcpToolResult(JSON.stringify(list.map((i) => JSON.parse(i.json) as unknown)));
  }
  if (norm === 'createpullrequest') {
    mcpSplitFullName(args);
    const missing = required(['owner', 'repo', 'title', 'head', 'base']);
    if (missing) return mcpToolResult(`Missing required argument: ${missing}`, true);
    const owner = String(args.owner);
    if (!repoRouteOwner(owner)) return mcpToolResult('Not Found', true);
    const repo = findRepo(String(args.repo));
    if (!repo) return mcpToolResult('Not Found', true);
    const head = String(args.head);
    const base = String(args.base);
    const headSha = repo.refs.get(`refs/heads/${head}`);
    const baseSha = repo.refs.get(`refs/heads/${base}`);
    if (!headSha || !baseSha) return mcpToolResult('Invalid head or base', true);
    const number = repo.nextNumber++;
    const pr: PullRequest = {
      id: nextGlobalId++, number, title: String(args.title), body: typeof args.body === 'string' ? args.body : '',
      state: 'open', merged: false, mergedAt: null, mergeCommitSha: null,
      headRef: head, baseRef: base, headSha, baseSha, user: ownerLogin(), createdAt: FIXED_ISO, updatedAt: FIXED_ISO, json: '', jsonBuf: EMPTY_BODY,
    };
    repo.pulls.push(pr);
    repo.pullsByNumber.set(number, pr);
    refreshPullJson(repo, pr);
    return mcpToolResult(pr.json);
  }
  if (norm === 'mergepullrequest') {
    mcpSplitFullName(args);
    const missing = required(['owner', 'repo', 'pull_number']);
    if (missing) return mcpToolResult(`Missing required argument: ${missing}`, true);
    const owner = String(args.owner);
    if (!repoRouteOwner(owner)) return mcpToolResult('Not Found', true);
    const repo = findRepo(String(args.repo));
    if (!repo) return mcpToolResult('Not Found', true);
    const pr = repo.pullsByNumber.get(Number(args.pull_number));
    if (!pr) return mcpToolResult('Pull request not found', true);
    if (pr.merged || pr.state === 'closed') return mcpToolResult('Pull request has already been merged', true);
    const merged = squashMerge(repo, pr);
    if (merged === null) return mcpToolResult('Merge conflict', true);
    return mcpToolResult(JSON.stringify({ sha: merged, merged: true, message: `Pull request #${pr.number} merged` }));
  }
  return mcpToolResult(`Unknown tool: ${name}`, true);
}

async function handleMcp(req: IncomingMessage, res: ServerResponse, bodyBuf: Buffer): Promise<boolean> {
  const method = req.method ?? 'GET';
  if (method === 'DELETE') {
    sendJson(res, 200, {});
    return true;
  }
  if (method !== 'POST') return false;
  const parsed = parseJsonBody(bodyBuf);
  if (!parsed.ok) {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return true;
  }
  const body = parsed.value as Record<string, unknown>;
  const id = body.id as string | number | null | undefined;
  const rpcMethod = typeof body.method === 'string' ? body.method : '';
  const params = (body.params ?? {}) as Record<string, unknown>;
  if (id === undefined || id === null) {
    // Notification: 202 with empty body.
    res.writeHead(202, { 'x-github-request-id': nextRequestId() });
    res.end();
    return true;
  }
  const ok = (result: unknown): void => sendJson(res, 200, { jsonrpc: '2.0', id, result });
  const fail = (code: number, message: string): void => sendJson(res, 200, { jsonrpc: '2.0', id, error: { code, message } });
  if (rpcMethod === 'server/discover') {
    ok({
      supportedVersions: ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26'],
      capabilities: { tools: {} },
      serverInfo: { name: 'forge-mcp', version: '1.0.0' },
      _meta: { 'io.modelcontextprotocol/serverInfo': { name: 'forge-mcp', version: '1.0.0' } },
    });
    return true;
  }
  if (rpcMethod === 'initialize') {
    ok({
      protocolVersion: '2025-11-25',
      capabilities: { tools: {} },
      serverInfo: { name: 'forge-mcp', version: '1.0.0' },
    });
    return true;
  }
  if (rpcMethod === 'ping') {
    ok({});
    return true;
  }
  if (rpcMethod === 'tools/list') {
    sendJsonText(res, 200, JSON.stringify({ jsonrpc: '2.0', id, result: JSON.parse(MCP_TOOLS_JSON) as unknown }));
    return true;
  }
  if (rpcMethod === 'tools/call') {
    const toolName = typeof params.name === 'string' ? params.name : '';
    const args = (params.arguments ?? {}) as Record<string, unknown>;
    const known = MCP_TOOLS.some((t) => String(t.name).toLowerCase().replace(/[^a-z0-9]/g, '') === toolName.toLowerCase().replace(/[^a-z0-9]/g, ''));
    if (!known) {
      fail(-32602, `Unknown tool: ${toolName}`);
      return true;
    }
    ok(handleMcpCall(toolName, args));
    return true;
  }
  if (rpcMethod.startsWith('notifications/')) {
    res.writeHead(202, { 'x-github-request-id': nextRequestId() });
    res.end();
    return true;
  }
  fail(-32601, `Method not found: ${rpcMethod}`);
  return true;
}

// ---------------------------------------------------------------------------
// Dispatcher + app factory
// ---------------------------------------------------------------------------

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  try {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    const pathname = url.pathname;
    const query = url.searchParams;
    // Hot path: GET/HEAD never carry a body in this protocol, so skip the
    // readBody await (its 'end' wait costs a scheduling round-trip per request).
    // Any GET that does declare a body still gets read, to keep keep-alive sane.
    const declaresBody = req.headers['transfer-encoding'] !== undefined || (req.headers['content-length'] !== undefined && req.headers['content-length'] !== '0');
    const bodyBuf = ((req.method === 'GET' || req.method === 'HEAD') && !declaresBody) ? EMPTY_BODY : await readBody(req);

    if (pathname === '/healthz') {
      if (req.method === 'GET') {
        sendJson(res, 200, { ok: true });
      } else {
        errJson(res, 404, 'Not Found');
      }
      return;
    }

    if (!authOk(req)) {
      errJson(res, 401, 'Unauthorized');
      return;
    }

    if (pathname === '/api/graphql' && req.method === 'POST') {
      const parsed = parseJsonBody(bodyBuf);
      if (!parsed.ok) {
        sendJson(res, 400, { errors: [{ message: 'Problems parsing JSON' }] });
        return;
      }
      if (Array.isArray(parsed.value)) {
        const results = (parsed.value as unknown[]).map((item) => executeGraphQL(item));
        sendJson(res, 200, results);
        return;
      }
      const result = executeGraphQL(parsed.value);
      sendJson(res, 200, result);
      return;
    }

    if (pathname === '/mcp') {
      if (await handleMcp(req, res, bodyBuf)) return;
      errJson(res, 404, 'Not Found');
      return;
    }

    if (pathname === '/api/v3' || pathname.startsWith('/api/v3/')) {
      const rest = pathname.slice('/api/v3'.length);
      const segs = rest.split('/').filter((s) => s !== '');
      if (await handleRest(req, res, segs, query, bodyBuf)) return;
      errJson(res, 404, 'Not Found');
      return;
    }

    const gitMatch = /^\/([^/]+)\/([^/]+)\.git(?:\/(.*))?$/.exec(pathname);
    if (gitMatch) {
      const owner = decodeSeg(gitMatch[1]!);
      const repoName = decodeSeg(gitMatch[2]!);
      const segs = (gitMatch[3] ?? '').split('/').filter((s) => s !== '');
      if (await handleGit(req, res, owner, repoName, segs, query, bodyBuf)) return;
      errJson(res, 404, 'Not Found');
      return;
    }

    errJson(res, 404, 'Not Found');
  } catch (err) {
    try {
      errJson(res, 500, err instanceof Error ? err.message : 'Internal Server Error');
    } catch {
      // Response already closed.
    }
  }
}

export function createApp(): Server {
  const server = createServer((req, res) => {
    void handleRequest(req, res);
  });
  return server;
}
