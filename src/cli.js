// CLI logic: parse args, load configs, run the check pipeline, write outputs.
import fs from 'node:fs';
import path from 'node:path';
import { loadConfigs, readStdin } from './config-load.js';
import { parseConfig, validateNode, renameUri } from './parse.js';
import { ensureCore } from './core-download.js';
import { testWithCore, coresForNode, fmtMs } from './checker.js';
import { buildDisplayName, uniquifyNames } from './geo.js';
import {
  buildSingboxConfig,
  buildPlainSubscription,
  buildBase64Subscription,
  buildReport,
} from './outputs.js';

const USAGE = `raysieve — find the proxy configs that actually work

Usage:
  raysieve <input.txt | directory | ->  [options]

Input: a file with one share-URI per line (vless/vmess/trojan/ss/hysteria2/tuic),
  a directory of such files, "-" for stdin, or base64 subscription content.

Options:
  -o, --out <dir>       output directory (default: out)
  --cores <list>        which cores to test with: xray, sing-box, or both (default: both)
  --timeout <ms>        per-node test timeout (default: 12000)
  --concurrency <n>     nodes tested in parallel (default: 8)
  --no-geo              skip exit-IP geo lookup (faster; names stay generic)
  --serve [port]        after checking, serve results over HTTP (default port 8080)
  --quiet               suppress progress output
  -h, --help            show this help

Outputs (written to --out):
  working.txt           working configs, one per line, renamed to exit location
  sub.txt               same, base64-encoded (importable as a subscription)
  sing-box.json         ready-to-use sing-box client config with all working nodes
  report.md             human-readable summary: what worked, what didn't, and why
`;

function parseArgs(argv) {
  const args = {
    inputs: [],
    out: 'out',
    cores: ['xray', 'sing-box'],
    timeout: 12000,
    concurrency: 8,
    geo: true,
    serve: null,
    quiet: false,
    help: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') args.help = true;
    else if (a === '-o' || a === '--out') args.out = argv[++i] ?? args.out;
    else if (a === '--cores') args.cores = String(argv[++i] ?? '').split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '--timeout') args.timeout = Number(argv[++i] ?? 12000);
    else if (a === '--concurrency') args.concurrency = Math.max(1, Number(argv[++i] ?? 8));
    else if (a === '--no-geo') args.geo = false;
    else if (a === '--quiet') args.quiet = true;
    else if (a === '--serve') {
      const next = argv[i + 1];
      if (next && /^\d+$/.test(next)) {
        args.serve = Number(next);
        i++;
      } else {
        args.serve = 8080;
      }
    } else if (a === '-') args.inputs.push('-');
    else if (a.startsWith('-')) {
      throw new Error(`unknown option: ${a}`);
    } else args.inputs.push(a);
  }
  return args;
}

export { USAGE, parseArgs };

export async function run(argv) {
  const args = parseArgs(argv);
  if (args.help || args.inputs.length === 0) {
    console.log(USAGE);
    process.exit(args.help ? 0 : 2);
  }
  const stdinText = args.inputs.includes('-') ? readStdin() : '';
  const { configs, skipped } = loadConfigs(args.inputs, { stdinText });
  const log = (msg) => {
    if (!args.quiet) process.stderr.write(msg + '\n');
  };
  log(`raysieve: ${configs.length} checkable configs loaded`);
  const started = Date.now();

  // Parse + validate each URI into a node object.
  const nodes = [];
  let parseFailures = 0;
  for (const uri of configs) {
    const node = parseConfig(uri);
    const err = validateNode(node);
    if (err) {
      parseFailures++;
      continue;
    }
    nodes.push(node);
  }

  // Resolve core binaries (download on first run).
  const binaries = {};
  for (const core of args.cores) {
    try {
      binaries[core] = await ensureCore(core);
      log(`raysieve: ${core} core ready (${binaries[core].source})`);
    } catch (e) {
      log(`raysieve: WARNING could not get ${core} core: ${e.message}`);
    }
  }
  if (Object.keys(binaries).length === 0) {
    console.error('raysieve: no proxy cores available; cannot test');
    process.exit(1);
  }

  // Check nodes with bounded concurrency.
  const working = [];
  const dead = [];
  let done = 0;
  const queue = nodes.slice();
  async function worker() {
    while (queue.length) {
      const node = queue.shift();
      const cores = coresForNode(node, Object.keys(binaries));
      let result = null;
      for (const core of cores) {
        result = await testWithCore(core, node, {
          binary: binaries[core].path,
          timeoutMs: args.timeout,
          geo: args.geo,
        });
        if (result.ok) break;
      }
      const entry = { node, ...result };
      if (result && result.ok) working.push(entry);
      else dead.push(entry);
      done++;
      if (!args.quiet) {
        const mark = result?.ok ? '✅' : '❌';
        const ms = result ? fmtMs(result.ms) : '-';
        process.stderr.write(`  [${done}/${nodes.length}] ${mark} ${node.scheme} ${node.host}:${node.port} ${ms}${result?.error ? ` — ${result.error}` : ''}\n`);
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(args.concurrency, nodes.length || 1) }, worker));

  // Name from measured exit geo.
  const named = working.map((w) => ({
    ...w,
    name: args.geo && w.geo && !w.geo.error ? buildDisplayName(w.node, w.geo) : w.node.name || w.node.host,
  }));
  uniquifyNames(named);
  const renamed = named.map((e) => ({ ...e, raw: renameUri(e.node, e.name) }));

  // Write outputs.
  fs.mkdirSync(args.out, { recursive: true });
  const plain = buildPlainSubscription(renamed);
  fs.writeFileSync(path.join(args.out, 'working.txt'), plain);
  fs.writeFileSync(path.join(args.out, 'sub.txt'), buildBase64Subscription(renamed));
  const sbcfg = buildSingboxConfig(renamed);
  if (sbcfg) fs.writeFileSync(path.join(args.out, 'sing-box.json'), JSON.stringify(sbcfg, null, 2));
  const report = buildReport({
    totals: { parsed: configs.length, checkable: nodes.length },
    working: renamed,
    skipped,
    dead,
    elapsedMs: Date.now() - started,
    noGeo: !args.geo,
  });
  fs.writeFileSync(path.join(args.out, 'report.md'), report);
  log(`raysieve: ${renamed.length} working / ${nodes.length} checked → ${args.out}/`);
  if (args.serve) {
    await serveDir(args.out, args.serve, args.quiet);
  }
  return renamed.length;
}

async function serveDir(dir, port, quiet) {
  const http = await import('node:http');
  const server = http.createServer((req, res) => {
    const name = String(req.url || '/').slice(1).split('?')[0] || 'working.txt';
    const safe = path.normalize(name).replace(/^([.][.][/\\])+/, '');
    const file = path.resolve(path.join(dir, safe));
    if (!file.startsWith(path.resolve(dir))) {
      res.writeHead(403);
      res.end('forbidden');
      return;
    }
    fs.readFile(file, (err, data) => {
      if (err) {
        res.writeHead(404);
        res.end('not found');
        return;
      }
      const ext = path.extname(file);
      const mime = ext === '.json' ? 'application/json' : ext === '.md' ? 'text/markdown' : 'text/plain; charset=utf-8';
      res.writeHead(200, { 'content-type': mime });
      res.end(data);
    });
  });
  await new Promise((r) => server.listen(port, () => r()));
  if (!quiet) process.stderr.write(`raysieve: serving ${dir}/ at http://0.0.0.0:${port}/ (ctrl-c to stop)\n`);
  return new Promise(() => {}); // run until killed
}
