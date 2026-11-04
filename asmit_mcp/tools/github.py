"""GitHub tools: public repository and user health.

Public data only, no token. Private repositories return "not found"
by GitHub's design, and this module reports that honestly instead of
pretending otherwise. Unauthenticated GitHub calls are subject to
GitHub's 60 requests/hour limit for shared IPs.
"""

from datetime import datetime, timezone

from asmit_mcp.core.errors import failure, success
from asmit_mcp.core.http import get_json
from asmit_mcp.core.validation import req_github_name, req_str


def _summarize_repo(data):
    pushed = data.get("pushed_at")
    days_since_push = None
    if pushed:
        pushed_dt = datetime.fromisoformat(pushed.replace("Z", "+00:00"))
        days_since_push = (datetime.now(timezone.utc) - pushed_dt).days
    return {
        "full_name": data.get("full_name"),
        "description": data.get("description"),
        "stars": data.get("stargazers_count"),
        "forks": data.get("forks_count"),
        "open_issues": data.get("open_issues_count"),
        "language": data.get("language"),
        "license": (data.get("license") or {}).get("spdx_id"),
        "last_push_days_ago": days_since_push,
        "url": data.get("html_url"),
    }


def _repo_or_failure(owner, repo):
    data, error = get_json(f"https://api.github.com/repos/{owner}/{repo}")
    if error:
        return None, failure(error[0], error[1])
    return data, None


def repo_health(owner: str, repo: str) -> str:
    """Health summary of a PUBLIC GitHub repository, plus upgrades:
    top languages by bytes and open pull requests counted from the
    first 100 open PRs. If those extra calls fail, they are reported
    as null instead of failing the whole health check.
    """
    owner = req_github_name(owner, "owner")
    repo = req_github_name(repo, "repo")
    data, failed = _repo_or_failure(owner, repo)
    if failed:
        return failed
    summary = _summarize_repo(data)
    languages, lang_error = get_json(
        f"https://api.github.com/repos/{owner}/{repo}/languages")
    if lang_error:
        summary["top_languages_by_bytes"] = None
    else:
        summary["top_languages_by_bytes"] = dict(
            sorted(languages.items(), key=lambda kv: -kv[1])[:5])
    pulls, pulls_error = get_json(
        f"https://api.github.com/repos/{owner}/{repo}/pulls"
        "?state=open&per_page=100")
    if pulls_error:
        summary["open_prs_sampled"] = None
        summary["open_prs_note"] = "Could not fetch open pull requests."
    else:
        summary["open_prs_sampled"] = len(pulls)
        summary["open_prs_note"] = (
            "Counted from the first 100 open pull requests.")
    return success(summary)


def repo_compare(owner1: str, repo1: str, owner2: str, repo2: str) -> str:
    """Side-by-side health comparison of two public GitHub repositories."""
    owner1 = req_github_name(owner1, "owner1")
    repo1 = req_github_name(repo1, "repo1")
    owner2 = req_github_name(owner2, "owner2")
    repo2 = req_github_name(repo2, "repo2")
    first, failed = _repo_or_failure(owner1, repo1)
    if failed:
        return failed
    second, failed = _repo_or_failure(owner2, repo2)
    if failed:
        return failed
    return success({"repo_a": _summarize_repo(first),
                    "repo_b": _summarize_repo(second)})


def github_user_summary(username: str) -> str:
    """Public summary of a GitHub user: profile, repo count, total stars
    across their public repos, and most-used languages. Public data only,
    no token; private repos are invisible to the public API by design."""
    username = req_str(username, "username", max_len=100)
    user, error = get_json(f"https://api.github.com/users/{username}")
    if error:
        return failure(error[0], error[1])
    repos, error = get_json(
        f"https://api.github.com/users/{username}/repos?per_page=100")
    if error:
        return failure(error[0], error[1])
    languages = {}
    total_stars = 0
    for repo in repos:
        lang = repo.get("language")
        if lang:
            languages[lang] = languages.get(lang, 0) + 1
        total_stars += repo.get("stargazers_count", 0)
    return success({
        "login": user.get("login"),
        "name": user.get("name"),
        "public_repos": user.get("public_repos"),
        "followers": user.get("followers"),
        "following": user.get("following"),
        "created_at": user.get("created_at"),
        "repos_fetched": len(repos),
        "total_stars_on_fetched_repos": total_stars,
        "top_languages": dict(sorted(languages.items(),
                                      key=lambda kv: -kv[1])[:5]),
        "profile_url": user.get("html_url"),
    })
