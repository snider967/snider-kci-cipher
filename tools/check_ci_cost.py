"""Enforce the zero-cost rule (decision D-025) on every GitHub Actions workflow in .github/workflows/.

Exit 0 if every workflow follows the rule, 1 with a list of violations otherwise. Line-based (no PyYAML needed), so
it is deliberately strict: anything it cannot recognise as safe is a violation.
  python3 -I tools/check_ci_cost.py
Copyright 2026 snider967. Licensed under the Apache License, Version 2.0.
"""
import glob, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Standard GitHub-hosted runners: free and unlimited minutes on public repositories. Larger runners (labels such as
# ubuntu-latest-4-cores, *-xlarge, *-gpu) are billed per minute even on public repositories, so they are not listed.
FREE_RUNNERS = {
    'ubuntu-24.04', 'ubuntu-22.04', 'ubuntu-latest', 'ubuntu-24.04-arm', 'ubuntu-22.04-arm',
    'macos-15', 'macos-14', 'macos-latest', 'windows-2025', 'windows-2022', 'windows-latest',
}
FIRST_PARTY_ACTIONS = ('actions/checkout@',)       # nothing that uploads, caches, publishes or calls a paid service
MAX_TIMEOUT = 20                                    # minutes per job
FORBIDDEN = [
    (r'^\s*schedule\s*:', 'scheduled runs (cron) are not allowed'),
    (r'actions/cache|cache\s*:', 'caches are not allowed (storage quota)'),
    (r'upload-artifact|upload-pages-artifact|deploy-pages', 'uploaded artifacts / Pages are not allowed (storage quota)'),
    (r'docker\s+push|npm\s+publish|twine\s+upload|gh\s+release', 'publishing packages or releases is not allowed'),
    (r'secrets\.(?!GITHUB_TOKEN\b)', 'secrets other than GITHUB_TOKEN are not allowed (no paid services)'),
    (r'self-hosted', 'self-hosted runners are not allowed'),
    (r'^\s*(packages|pages|id-token|deployments)\s*:\s*write', 'write permissions for packages/pages/deployments are not allowed'),
]

def check(path):
    errs = []
    text = open(path, encoding='utf-8').read()
    lines = text.splitlines()
    code = [l.split(' #')[0] if not l.lstrip().startswith('#') else '' for l in lines]

    for i, l in enumerate(code, 1):
        for pat, why in FORBIDDEN:
            if re.search(pat, l):
                errs.append(f'{path}:{i}: {why}')
        m = re.match(r'\s*-?\s*uses\s*:\s*(\S+)', l)
        if m and not m.group(1).startswith(FIRST_PARTY_ACTIONS):
            errs.append(f'{path}:{i}: action {m.group(1)} is not on the allowed list')
        m = re.search(r'\bos\s*:\s*([\w.-]+)', l)                     # matrix entries
        if m and m.group(1) not in FREE_RUNNERS:
            errs.append(f'{path}:{i}: runner {m.group(1)} is not a free standard runner')
        m = re.match(r'\s*runs-on\s*:\s*(.+?)\s*$', l)
        if m:
            label = m.group(1).strip('\'"')
            if label != '${{ matrix.os }}' and label not in FREE_RUNNERS:
                errs.append(f'{path}:{i}: runner {label} is not a free standard runner')
        m = re.match(r'\s*timeout-minutes\s*:\s*(\d+)', l)
        if m and int(m.group(1)) > MAX_TIMEOUT:
            errs.append(f'{path}:{i}: timeout {m.group(1)} min is above the {MAX_TIMEOUT}-minute cap')

    if not re.search(r'^concurrency\s*:', text, re.M) or 'cancel-in-progress: true' not in text:
        errs.append(f'{path}: needs a top-level concurrency group with cancel-in-progress: true')

    # each job (2-space-indented key under "jobs:") needs a timeout and the public-repository guard
    in_jobs, job, body = False, None, {}
    for l in code:
        if re.match(r'^jobs\s*:', l):
            in_jobs = True
            continue
        if in_jobs and re.match(r'^\S', l):
            in_jobs = False
        if in_jobs:
            m = re.match(r'^  ([\w-]+)\s*:\s*$', l)
            if m:
                job = m.group(1)
                body[job] = []
            elif job:
                body[job].append(l)
    if not body:
        errs.append(f'{path}: no jobs found')
    for job, ls in body.items():
        if not any(re.match(r'^    timeout-minutes\s*:', l) for l in ls):
            errs.append(f'{path}: job {job} has no job-level timeout-minutes')
        if not any(re.match(r"^    if\s*:\s*\$\{\{\s*!github\.event\.repository\.private\s*\}\}", l) for l in ls):
            errs.append(f'{path}: job {job} lacks "if: ${{{{ !github.event.repository.private }}}}"')
    return errs

def main():
    files = sorted(glob.glob(os.path.join(ROOT, '.github', 'workflows', '*.y*ml')))
    errs = [e for f in files for e in check(f)]
    for e in errs:
        print('check_ci_cost:', os.path.relpath(e, ROOT) if e.startswith(ROOT) else e, file=sys.stderr)
    print(f'check_ci_cost: {len(files)} workflow(s), {len(errs)} violation(s)')
    return 1 if errs or not files else 0

if __name__ == '__main__':
    sys.exit(main())
