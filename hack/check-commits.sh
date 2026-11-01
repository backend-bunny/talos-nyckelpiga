#!/usr/bin/env bash
# Fail unless the PR title and every commit subject in BASE..HEAD are
# Conventional Commits (type(scope)!: subject), which release-please needs to
# pick the next version and write the changelog.
# Usage: hack/check-commits.sh BASE HEAD [PR_TITLE]
set -euo pipefail
cd "$(dirname "$0")/.."

base=${1:?usage: hack/check-commits.sh BASE HEAD [PR_TITLE]} head=${2:?} title=${3:-}
types='feat|fix|perf|revert|build|deps|docs|ci|chore|test|refactor|style'
pattern="^($types)(\([a-z0-9._/-]+\))?!?: .+"

bad=0
check() {
  if [[ ! $2 =~ $pattern ]]; then
    echo "not a Conventional Commit ($1): $2" >&2
    bad=1
  fi
}
[[ -z $title ]] || check "PR title" "$title"
while IFS= read -r subject; do
  # Merge commits from updating the branch are fine.
  [[ $subject == Merge\ * ]] && continue
  check commit "$subject"
done < <(git log --format=%s "$base..$head")

if (( bad )); then
  echo "Use <type>[(scope)][!]: <subject>, type one of: ${types//|/, }" >&2
  exit 1
fi
echo "commit messages OK"
