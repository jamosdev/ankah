#!/usr/bin/env bash
# Return this checkout to mastah and accept only a fast-forward from origin.
set -euo pipefail

blocked() {
    printf 'BLOCKED [%s]: %s\n' "$1" "$2" >&2
    exit 1
}

if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
    script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
else
    # Supports: git show mastah:pull_up.sh | bash (from the repository root).
    script_dir=$(pwd -P)
fi
cd "$script_dir"

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || blocked NOT_REPOSITORY 'Run the checked-in script from its repository.'
[[ "$repo_root" == "$script_dir" ]] || blocked WRONG_LOCATION 'The script must be at the repository root.'

for state in MERGE_HEAD CHERRY_PICK_HEAD REVERT_HEAD REBASE_HEAD rebase-apply rebase-merge sequencer; do
    state_path=$(git rev-parse --git-path "$state")
    if [[ -e "$state_path" ]]; then
        blocked OPERATION_IN_PROGRESS "Finish or abort the Git operation recorded at $state_path."
    fi
done

worktree_status=$(git status --porcelain=v1 --untracked-files=all --ignore-submodules=none) || blocked STATUS_FAILED 'Could not inspect the working tree.'
if [[ -n "$worktree_status" ]]; then
    git status --short --untracked-files=all --ignore-submodules=none >&2
    blocked DIRTY_WORKTREE 'Commit, stash, or otherwise resolve these files before retrying.'
fi

git show-ref --verify --quiet refs/heads/mastah || blocked NO_LOCAL_BRANCH 'Local branch mastah is missing.'
[[ "$(git config --get branch.mastah.remote || :)" == origin ]] || blocked WRONG_UPSTREAM 'Configure mastah to track origin/mastah.'
[[ "$(git config --get branch.mastah.merge || :)" == refs/heads/mastah ]] || blocked WRONG_UPSTREAM 'Configure mastah to track origin/mastah.'
git remote get-url origin >/dev/null 2>&1 || blocked NO_REMOTE 'Remote origin is missing.'

current_branch=$(git symbolic-ref --quiet --short HEAD || :)
if [[ -n "$current_branch" && "$current_branch" != mastah ]]; then
    blocked OTHER_BRANCH "Currently on $current_branch; switch to mastah yourself if that is intended."
fi

if [[ -z "$current_branch" ]] && ! git merge-base --is-ancestor HEAD refs/heads/mastah; then
    detached_tip=$(git rev-parse HEAD)
    rescue_branch="rescue/pull-up-$detached_tip"
    if ! git show-ref --verify --quiet "refs/heads/$rescue_branch"; then
        git branch "$rescue_branch" "$detached_tip" || blocked RESCUE_FAILED 'Could not create a branch for the detached commits.'
    fi
    blocked DETACHED_COMMITS "Detached HEAD has commits outside mastah. Saved them on $rescue_branch; review or merge them before retrying."
fi

local_tip=$(git rev-parse refs/heads/mastah)
if ! git -c submodule.recurse=false fetch --no-tags --no-recurse-submodules origin refs/heads/mastah; then
    blocked FETCH_FAILED 'Could not fetch origin/mastah; the working branch was not changed.'
fi
remote_tip=$(git rev-parse --verify 'FETCH_HEAD^{commit}') || blocked FETCH_FAILED 'Fetch did not provide a commit.'

if git merge-base --is-ancestor "$local_tip" "$remote_tip"; then
    direction=forward
elif git merge-base --is-ancestor "$remote_tip" "$local_tip"; then
    direction=ahead
else
    blocked DIVERGED "mastah ($local_tip) and origin/mastah ($remote_tip) have diverged; reconcile them manually."
fi

[[ "$(git rev-parse refs/heads/mastah)" == "$local_tip" ]] || blocked BRANCH_MOVED 'mastah changed during the checks; retry.'

# Git may overwrite ignored files during a fast-forward. Check every path that
# will become tracked before switching branches or updating the working tree.
added_paths=$(mktemp) || blocked TEMP_FAILED 'Could not create a temporary file for path checks.'
trap 'rm -f "$added_paths"' EXIT
git diff --name-only -z --no-renames --diff-filter=A HEAD "$remote_tip" -- > "$added_paths" || blocked DIFF_FAILED 'Could not inspect incoming paths.'
while IFS= read -r -d '' path; do
    if [[ -e "$path" || -L "$path" ]]; then
        blocked PATH_COLLISION "Incoming tracked path $path already exists in the working tree. Move or back it up before retrying."
    fi
    parent=$(dirname -- "$path")
    while [[ "$parent" != . ]]; do
        if [[ -L "$parent" || ( -e "$parent" && ! -d "$parent" ) ]]; then
            blocked PATH_COLLISION "Incoming tracked path $path has an existing non-directory or symlink at $parent."
        fi
        parent=$(dirname -- "$parent")
    done
done < "$added_paths"

if [[ -z "$current_branch" ]]; then
    git -c submodule.recurse=false switch --no-overwrite-ignore mastah || blocked SWITCH_FAILED 'Could not switch to mastah; the working tree was preserved.'
fi

if [[ "$direction" == forward && "$local_tip" != "$remote_tip" ]]; then
    git -c submodule.recurse=false merge --ff-only "$remote_tip" || blocked MERGE_FAILED 'Fast-forward failed; inspect git status before retrying.'
fi

if [[ "$direction" == ahead ]]; then
    printf 'On mastah at %s. Local commits are ahead of origin/mastah; nothing was discarded.\n' "$(git rev-parse --short HEAD)"
else
    printf 'On mastah at %s. Up to date with fetched origin/mastah.\n' "$(git rev-parse --short HEAD)"
fi
