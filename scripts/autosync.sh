#!/usr/bin/env bash
# Auto-commit and push this repo to origin/main. Run by the Claude Code Stop hook (.claude/settings.local.json)
# at the end of every Claude turn; also safe to run by hand: bash scripts/autosync.sh
# Guards: only on branch main, skips while another git operation is running, never commits files over 95 MB
# (GitHub rejects >100 MB), refuses to commit anything that looks like a credential, and rebases onto a
# teammate's newer push before pushing. Prints a one-line {"systemMessage": ...} only when something happened.
set -u
cd "$(dirname "$0")/.." || exit 0
g=$(git rev-parse --git-dir 2>/dev/null) || exit 0
export GIT_TERMINAL_PROMPT=0

say() { printf '{"systemMessage": "Auto-sync: %s"}\n' "$1"; }

[ "$(git symbolic-ref --short HEAD 2>/dev/null)" = main ] || exit 0
if [ -e "$g/index.lock" ] || [ -d "$g/rebase-merge" ] || [ -d "$g/rebase-apply" ] || [ -e "$g/MERGE_HEAD" ]; then
  exit 0
fi

lock="$g/autosync.lock"                       # one sync at a time across concurrent Claude sessions
find "$lock" -maxdepth 0 -mmin +10 -exec rmdir {} \; 2>/dev/null
mkdir "$lock" 2>/dev/null || exit 0
trap 'rmdir "$lock" 2>/dev/null' EXIT

git add -A 2>/dev/null                       # silence CRLF warnings; stdout must stay pure JSON for the hook
skipped=""
while IFS= read -r -d '' f; do
  if [ -f "$f" ] && [ "$(stat -c %s "$f")" -gt 95000000 ]; then
    git reset -q -- "$f"
    skipped="$skipped $f"
  fi
done < <(git diff --cached --name-only -z --diff-filter=AM)

if git diff --cached -U0 | grep -qE '^\+.*(ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|hf_[A-Za-z0-9]{30,}|sk-[A-Za-z0-9_-]{30,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY)'; then
  git reset -q
  say "NOT committed - the changes look like they contain a credential. Review git diff and commit by hand."
  exit 0
fi

n=0
if ! git diff --cached --quiet; then
  n=$(git diff --cached --name-only | wc -l | tr -d ' ')
  git commit -q -m "Auto-sync: $n file(s) changed" \
    -m "$(git diff --cached --name-status | head -n 40)" \
    -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" || exit 0
fi

[ -n "$(git rev-list origin/main..HEAD 2>/dev/null)" ] || { [ -n "$skipped" ] && say "skipped files over 95 MB:$skipped"; exit 0; }

err="$g/autosync.err"
if ! git push -q origin HEAD:main 2>"$err"; then
  if git pull -q --rebase --autostash origin main 2>>"$err"; then
    git push -q origin HEAD:main 2>>"$err" || { say "committed locally, push failed - see .git/autosync.err"; exit 0; }
  else
    git rebase --abort 2>/dev/null
    say "committed locally, but GitHub has conflicting changes - needs a manual merge"
    exit 0
  fi
fi

msg="pushed to GitHub ($(git rev-parse --short HEAD), $n file(s) committed)"
[ -n "$skipped" ] && msg="$msg; skipped files over 95 MB:$skipped"
say "$msg"
