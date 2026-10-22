# nodejs-security-check

An agent skill in the open [Agent Skills](https://agentskills.io) `SKILL.md` format that checks a Node.js project against the
[Node.js security release of 2026-10-21](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
— CVE-2026-111497, an out-of-bounds write in the Brotli decoder that allows remote code execution,
plus nine more — and bumps version pins to the patched release.

Patched versions: **22.23.4**, **24.22.1**, **26.12.1**. Node 20 and older are end-of-life and get no fix.

## What it checks

- **Version pins**: `.nvmrc`, `.node-version`, `.tool-versions`, `package.json` (`engines`, `volta`),
  Dockerfiles, compose files, GitHub Actions, GitLab CI and CircleCI configs
- **Lambda and Firebase runtimes**: `runtime: nodejs20.x` in `serverless.yml` / `serverless.ts` / SAM / Terraform,
  CDK `Runtime.NODEJS_20_X`, `firebase.json` — EOL majors move to `nodejs22.x` or `nodejs24.x` with `--target-major`
- **undici installed from npm**: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
- **Source code that touches the affected APIs**: Brotli decoding, `dns.resolve*`, TLS hostname checks,
  `rejectUnauthorized: false`, keep-alive agents, startup snapshots / SEA, the permission model

Floating tags such as `node:22` or `lts/*` are reported as "rebuild required" and never edited.

## Install

Clone it into your agent's skills directory:

| Scope | Path |
| --- | --- |
| One project | `<repo>/.claude/skills/nodejs-security-check/` |
| Every project | `~/.claude/skills/nodejs-security-check/` |

```bash
git clone https://github.com/Sami-AlEsh/nodejs-security-check ~/.claude/skills/nodejs-security-check
```

Then type `/nodejs-security-check` in a session, or just ask *"is this project affected by the Node.js CVEs?"*.
Any agent that supports the Agent Skills format works the same way.

## Run the script on its own

No agent needed, zero dependencies, any current Node:

```bash
node scripts/check.mjs .                           # report
node scripts/check.mjs . --json                    # machine-readable
node scripts/check.mjs . --fix                     # bump pins within their own major line
node scripts/check.mjs . --fix --target-major 24   # move every pin to 24.22.1 (needed for EOL lines)
```

Exit code `0` = no project pin is left vulnerable, `1` = unresolved pins, `2` = bad arguments.
The `[RUNTIME]` line about the Node running the check is informational and does not affect the exit code.

## What it does not do

- Upgrade the Node on your machine or inside a running container — it tells you the command instead
- Prove what is deployed: an image built long ago or a function edited in a console is out of its reach
- Replace the upgrade: the code-level findings are defense in depth, not a fix

## Files

```
SKILL.md              workflow for the agent
scripts/check.mjs     the scanner / fixer
references/cves.md    the ten CVEs, which code pattern each needs, and mitigations
```
