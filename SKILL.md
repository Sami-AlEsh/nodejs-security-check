---
name: nodejs-security-check
description: Detect and fix Node.js projects affected by the October 21, 2026 Node.js security release (CVE-2026-111497 Brotli decoder RCE, CVE-2026-105482, CVE-2026-105483, CVE-2026-106069, CVE-2026-106072, CVE-2026-105481, CVE-2026-106074 and others). Use this skill whenever the user mentions Node.js vulnerabilities, security releases, CVEs, patching or upgrading Node, auditing a Node project, Dockerfiles or CI using node images, .nvmrc, or asks "is my project affected" or "am I secure" in any Node.js, npm, Express, NestJS, Next.js, or TypeScript backend context, even if they do not name the specific CVEs.
allowed-tools: Bash, Read, Edit, Grep, Glob
argument-hint: "[project dir] [--fix] [--target-major 22|24|26]"
---

# Node.js October 2026 Security Release Check

The Node.js project shipped security releases on 2026-10-21 for the 26.x, 24.x and 22.x lines.
Patched versions: **22.23.4**, **24.22.1**, **26.12.1**. Any other major line (18, 20, 21, 23, 25 and older) is
end-of-life and has no fix: it is affected and must move to a supported line.

Source: https://nodejs.org/en/blog/vulnerability/october-2026-security-releases
Full CVE list and which code patterns each affects: `references/cves.md`.

`<skill-dir>` below is the directory that contains this SKILL.md.

## Workflow

1. **Detect.** From the project root, run:
   ```bash
   node <skill-dir>/scripts/check.mjs .
   ```
   Add `--json` for machine output. It inspects the running Node, `.nvmrc`, `.node-version`,
   `.tool-versions`, `package.json` (`engines`, `volta`), Dockerfiles, compose files, CI configs
   (GitHub Actions, GitLab CI, CircleCI), and the `undici` version in npm, yarn and pnpm lockfiles.
   It also scans source for code that touches the vulnerable APIs. It skips `node_modules`, build
   output, `.claude`, and every plain directory named in the root `.gitignore`.
2. **Report** the findings to the user before changing anything: which files pin a vulnerable
   version, and which source files use risky APIs.
3. **Fix** version pins:
   ```bash
   node <skill-dir>/scripts/check.mjs . --fix
   ```
   This bumps pinned versions within the same major line to the patched release (for example
   `node:22.10.0-alpine` becomes `node:22.23.4-alpine`). It never changes a major version on its own.
   For EOL majors, ask the user which supported line to move to (24.x LTS is the usual choice),
   then rerun with `--fix --target-major 24`. With `--target-major`, every pin moves to that line,
   including pins already on a supported line, so the project ends up on one version. Show the user
   `git diff` afterwards.
4. **Runtime upgrade.** The script cannot upgrade the Node installed on a machine. Tell the user
   the right command for their manager (`nvm install 24.22.1`, `fnm install 24.22.1`,
   `volta install node@24.22.1`, `n 24.22.1`, or a fresh `docker pull`/rebuild with `--pull`).
5. **Code-level findings.** For each source hit, read the file and apply the mitigation from
   `references/cves.md` only when the code really handles untrusted input. Do not blanket-edit.
   Upgrading Node is the real fix; code changes are defense in depth.
6. **Verify.** Rerun the check: exit 0 means no project pin is still vulnerable (the `[RUNTIME]` line
   about the Node running the check is informational and never affects the exit code). Run the
   project's tests, and confirm `node --version` inside the built container or CI job.

## Notes on floating tags

`node:22`, `node:24-alpine`, `node:lts` and `lts/*` are not pinned, so they are fixed only when the
image is rebuilt or the runner cache refreshes. The script reports these as "floating: rebuild
required" and does not edit them. Suggest `docker build --pull --no-cache` and, if the user
wants reproducibility, pinning to the exact patched tag.

## Guardrails

- Never edit files outside the project directory or touch `node_modules`.
- Do not claim a project is safe from the script exit code alone when floating tags or CI
  runtime are involved. Say what was and was not verified.
- If the date is well past 2026-10-21, newer Node security releases may exist. Check
  https://nodejs.org/en/blog/vulnerability and mention it; the patched versions above are
  the minimum, not necessarily the latest.
- `undici` is bundled in Node and also installed from npm by many projects. Its fixed
  version is not listed on the Node advisory, so the script reports installed versions and
  recommends updating to the latest release; check the undici advisories for the exact version.
