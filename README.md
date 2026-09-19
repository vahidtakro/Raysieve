# 🧅 raysieve

**Feed it a pile of proxy configs. Get back only the ones that actually work — renamed to where they really exit.**

raysieve takes share-URIs (`vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria2://`, `tuic://` — the kind you collect from Telegram channels, subscription links, or your own servers), **boots a real proxy core for each one, pushes actual HTTP traffic through it**, and keeps only the configs that really pass. Every survivor gets renamed to its **measured exit location**: country flag, country code, and city.

```
$ raysieve configs.txt
raysieve: 37 checkable configs loaded
raysieve: xray core ready (managed)
raysieve: sing-box core ready (managed)
  [ 1/37] ❌ vless 188.114.97.6:8080 1.2s — socks reply 1
  [ 2/37] ✅ vless 104.21.70.21:8080 2.4s
  ...
raysieve: 6 working / 37 checked → out/
```

```text
# out/working.txt
vless://...@104.21.70.21:8080?...#%F0%9F%87%A9%F0%9F%87%AA%20DE%20%C2%B7%20Frankfurt%20am%20Main
trojan://...@188.114.96.3:443?...#%F0%9F%87%B8%F0%9F%87%AC%20SG%20%C2%B7%20Singapore
```

No dependencies. No config files. Works on any Linux server (and macOS/Windows), on x64 and ARM.

---

## Why raysieve

Leaked/public proxy configs rot fast — usually most of a fresh batch is already dead, and the ones that live rarely match the name someone gave them. raysieve answers two questions honestly:

1. **Does this config actually carry traffic right now?** — verified with real requests through the tunnel (not a lazy TCP-port ping, which lies constantly on Cloudflare-fronted nodes).
2. **Where does my traffic actually exit?** — the geo lookup runs *through the proxy itself* (`ip-api.com` via the tunnel), so names reflect the true exit, not the entry IP, not the feed author's wishful tag. Original tags like `[OpenRay] 🇨🇦 CA-29537` are **discarded and rebuilt** from measurement.

## Install

Requirements: **Node.js ≥ 18.17** and outbound internet access. That's it.

```bash
git clone https://github.com/vahidtakro/raysieve.git
cd raysieve
npm test                     # optional sanity check
```

On first run raysieve downloads `xray-core` and `sing-box` release binaries for your platform into a cache dir (uses a system copy automatically if one is on `PATH`). No root needed.

Or with Docker:

```bash
docker build -t raysieve .
docker run --rm -v "$PWD:/work" -w /work raysieve configs.txt --out out
```

## Usage

```bash
raysieve <file|directory|->  [options]
```

| Input | Meaning |
|---|---|
| `configs.txt` | file with one URI per line (also accepts base64 subscription files — auto-detected) |
| `https://…/list.txt` | **remote list over HTTP(S)** — fetched automatically (plain or base64 sub, auto-detected) |
| `./more-configs/` | directory: every `*.txt`/`*.conf`/`*.list` inside is loaded |
| `-` | read URIs from stdin (`cat list.txt \| raysieve -`) |

Mix and match — files, URLs, directories and stdin can be combined in one run. Lines starting with `#` are comments. Duplicates are removed automatically.

### Importing remote config lists

Most public config channels publish ready-made lists (often base64 subscriptions) on GitHub or their own servers. Just pass the URL:

```bash
# a plain URI-per-line list:
raysieve https://raw.githubusercontent.com/username/repo/refs/heads/main/output/example.txt

# a base64 subscription URL works identically — it's auto-detected and decoded:
raysieve https://some-provider.example/sub?token=abc123

# combine a remote list with your own local file, then serve the results:
raysieve https://raw.githubusercontent.com/username/repo/refs/heads/main/output/example.txt\
         my-extra-configs.txt -o /var/www/sub --serve 8080
```

raysieve fetches the URL (following redirects, 20 s timeout, 20 MB size cap), decodes it if it's base64, merges and dedupes everything, then tests it like any other input. Failed fetches warn and continue, so one dead mirror won't sink a batch.

| Option | Default | Meaning |
|---|---|---|
| `-o, --out <dir>` | `out` | where results are written |
| `--cores <list>` | `xray,sing-box` | cores to test with (`--cores sing-box` covers every scheme alone) |
| `--timeout <ms>` | `12000` | per-node budget (connect + 2 HTTP targets + geo) |
| `--concurrency <n>` | `8` | nodes tested in parallel |
| `--no-geo` | off | skip exit-IP lookup (faster; names keep their original tags) |
| `--serve [port]` | off | after checking, serve the output dir over HTTP (default `:8080`) |
| `--quiet` | off | suppress progress lines |

### What you get

```
out/
├── working.txt      # working URIs, renamed to exit location — one per line
├── sub.txt          # same list, base64-encoded → import as a subscription URL
├── sing-box.json    # ready-to-run sing-box client config with ALL working nodes
└── report.md        # summary: what survived, what died, and why
```

- **`working.txt`** — paste anywhere clients accept URI lists.
- **`sub.txt`** — host it anywhere (GitHub raw, nginx, S3, `--serve`) and add it as a subscription URL in v2rayNG / Hiddify / NekoBox / Shadowrocket. Base64 subscription format is universally supported.
- **`sing-box.json`** — drop-in config: a SOCKS5 local inbound (`127.0.0.1:2080`) plus one outbound per working node behind a `selector` — flip between them in any sing-box GUI, or use the `auto` outbound directly.
- **`report.md`** — human-readable audit trail with per-node error messages for the dead ones.

### Scheduling it

Config rot means you should re-run regularly. A cron entry that re-fetches a remote list, re-tests it, and republishes a fresh subscription every 30 minutes:

```cron
*/30 * * * * cd /opt/raysieve && ./bin/raysieve.js https://raw.githubusercontent.com/username/repo/refs/heads/main/output/example.txt -o /var/www/sub --quiet
```

Point your clients at `http://your-server/sub.txt` (via the `--serve` mode, or nginx on that dir) and they always import a fresh, tested list. For huge remote lists (10k+), add `--timeout 8000 --concurrency 16` to keep runs snappy.

---

## How the checking works

For every node, in a bounded-parallel pool:

1. **Parse & validate** the URI into a protocol-neutral node object.
2. **Generate** a real xray-core or sing-box config with that node as the only outbound and a local SOCKS5 inbound on a fresh loopback port.
3. **Boot the actual core binary** (xray speaks vless/vmess/trojan/ss; sing-box adds hysteria2/tuic).
4. **Push real HTTP traffic** through it: `GET http://www.gstatic.com/generate_204` and `GET http://www.google.com/generate_204` via the local SOCKS judge. Any valid HTTP response = the tunnel works end-to-end.
5. **Measure the exit**: `GET http://ip-api.com/json/...` *through the same tunnel* → country/city/ISP of the IP your traffic really leaves from.
6. **Rename & emit**: flag + country + city become the new tag; name collisions get `#2`, `#3`, …

If a "server" is just a Cloudflare edge that accepts TCP but the worker behind it is dead, step 4 fails it. If a config claims to be in Canada but exits from a datacenter in Frankfurt, step 5 names it Frankfurt — measured, not claimed.

> **A note on Cloudflare-fronted nodes**: most public configs ride on `*.workers.dev`. Their exit IP is whatever Cloudflare's egress gives the worker, so the measured country is often **US** even when the feed tagged them otherwise. That's not a bug — it's where your traffic actually exits.

## Extending

- **New protocol**: add a parser in `src/parse.js`, an outbound in `src/builders.js` (xray, sing-box, or both), and a `coresForNode` rule in `src/checker.js`.
- **Different test targets**: edit `TARGETS` in `src/checker.js` (keep them plain-HTTP and hyper-reliable).
- **Geo provider**: `lookupGeoViaSocks` in `src/checker.js` — swap in any IP-echo API returning JSON.

## Honest limitations

- UDP, REALITY (urltest-style fingerprinting), XTLS vision flows and ssr/socks/http schemes parse but are **not fully verified** — REALITY/XTLS configs are tested with TLS semantics; full support tracks upstream cores.
- The exit-geo of CDN-fronted nodes is the CDN's egress (see note above).
- Testing many dead nodes costs time: each dead node burns up to `--timeout` ms. Batch sizes in the hundreds are fine; tens of thousands want a beefier box or lower timeout.

## License

GPL-3.0 — see [LICENSE](LICENSE). Use responsibly; respect the laws of your jurisdiction and the terms of any services you point this at.
