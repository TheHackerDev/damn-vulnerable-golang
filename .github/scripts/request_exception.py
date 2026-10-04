"""
request_exception.py

Triggered by a PR comment like:

    /request-exception We need this in prod for the Q4 launch, will fix by Nov 15

Flow:
  1. Parse the reason out of the comment.
  2. Find the ArmorCode findings tied to this repo (via the finding search API).
  3. Check whether a standing exception already covers this repo's product/
     subproduct (via the "assignable" helper endpoint). If yes, append the
     findings to it. If no, create a new exception with the given reason
     and a rolling expiry.
  4. Post a confirmation comment back on the PR with a link to the exception.

Two things below are flagged NEEDS_VERIFICATION because the codebase search
that produced this endpoint list could not confirm them from the controller
signatures alone. Check them against your tenant's live Swagger/OpenAPI
doc before relying on this in production:
  - The exact filter key for "repository name" in the finding search body.
  - The exact route for looking up a product's business unit ID (the
    subproduct-by-product route IS confirmed; the product/BU lookup is not).
"""

import os
import re
import sys
import requests

ARMORCODE_BASE_URL = os.environ["ARMORCODE_BASE_URL"].rstrip("/")
ARMORCODE_API_TOKEN = os.environ["ARMORCODE_API_TOKEN"]
GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
PR_NUMBER = os.environ["PR_NUMBER"]
REPO = os.environ["REPO"]  # e.g. "wayfair/ph-inbound-order-terraform"
COMMENT_BODY = os.environ["COMMENT_BODY"]
COMMENT_AUTHOR = os.environ["COMMENT_AUTHOR"]

REPO_NAME = REPO.split("/")[-1]

armorcode_headers = {
    "Authorization": f"Bearer {ARMORCODE_API_TOKEN}",
    "Content-Type": "application/json",
}

github_headers = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
}


def parse_reason(comment_body: str) -> str:
    """Pull the free-text reason out of '/request-exception <reason>'."""
    match = re.match(r"^/request-exception\s+(.*)$", comment_body.strip(), re.DOTALL)
    if not match or not match.group(1).strip():
        return "No reason provided by requester; follow up before approving."
    return match.group(1).strip()


def find_findings_for_repo(repo_name: str) -> list[dict]:
    """
    POST /user/findings

    NEEDS_VERIFICATION: the filter key used here ("repositoryName") is our
    best read of the finding property name confirmed in the code
    (CrgGraphService references repositoryName / repositoryUrl on findings),
    but the finding-search filter key spelling itself was not confirmed by
    the controller search. Check the deployed OpenAPI schema for the exact
    key (it may be namespaced, e.g. "repository.name" or similar) and adjust
    the body below before relying on this in production.
    """
    body = {
        "filters": {
            "repositoryName": [repo_name],
            "status": ["OPEN", "CONFIRMED"],
        },
        "page": 0,
        "size": 200,
    }
    resp = requests.post(
        f"{ARMORCODE_BASE_URL}/user/findings", headers=armorcode_headers, json=body
    )
    resp.raise_for_status()
    data = resp.json()
    # Adjust this if your tenant's response wraps results differently
    # (e.g. data["content"] vs data["findings"] vs top-level list).
    return data.get("content", data.get("findings", []))


def find_assignable_exception(finding_ids: list[int]) -> dict | None:
    """
    POST /api/risk-register/assignable

    Returns exceptions that could accept findings matching this filter,
    letting us reuse an existing standing exception for the repo/subproduct
    instead of creating a new one every time.
    """
    body = {"findingFilterRequest": {"filters": {"id": finding_ids}}}
    resp = requests.post(
        f"{ARMORCODE_BASE_URL}/api/risk-register/assignable",
        headers=armorcode_headers,
        json=body,
    )
    resp.raise_for_status()
    candidates = resp.json()
    return candidates[0] if candidates else None


def create_exception(product_ids: list[int], reason: str) -> dict:
    """
    POST /api/risk-register

    Creates a brand-new exception scoped to the repo's product(s). Expiry
    is set to 90 days out as a default "standing exception" window; adjust
    to whatever cadence your security team wants to re-review at.
    """
    body = {
        "name": f"Auto-requested exception: {REPO_NAME}",
        "productIds": product_ids,
        "justification": reason,
        "expiryDate": "2027-01-01T00:00:00Z",  # TODO: compute dynamically (e.g. now + 90 days)
        "findingFilters": {"filters": {"repositoryName": [REPO_NAME]}},
    }
    resp = requests.post(
        f"{ARMORCODE_BASE_URL}/api/risk-register", headers=armorcode_headers, json=body
    )
    resp.raise_for_status()
    return resp.json()


def append_findings_to_exception(finding_ids: list[int], exception_id: int) -> None:
    """
    PUT /user/findings/bulk/assign-risk-register

    riskRegisterUpdateMode=APPEND is important: it adds this exception to
    each finding's existing exception list rather than replacing it.
    """
    body = {
        "findingIds": finding_ids,
        "riskRegister": [exception_id],
        "riskRegisterUpdateMode": "APPEND",
        "findingFilterRequest": {"filters": {}},
        "comment": f"Requested via GitHub PR #{PR_NUMBER} by {COMMENT_AUTHOR}",
    }
    resp = requests.put(
        f"{ARMORCODE_BASE_URL}/user/findings/bulk/assign-risk-register",
        headers=armorcode_headers,
        json=body,
    )
    resp.raise_for_status()


def post_pr_comment(message: str) -> None:
    url = f"https://api.github.com/repos/{REPO}/issues/{PR_NUMBER}/comments"
    resp = requests.post(url, headers=github_headers, json={"body": message})
    resp.raise_for_status()


def main() -> None:
    reason = parse_reason(COMMENT_BODY)

    findings = find_findings_for_repo(REPO_NAME)
    if not findings:
        post_pr_comment(
            "Could not find any open ArmorCode findings for this repository. "
            "If this seems wrong, check that the repo is connected to ArmorCode."
        )
        return

    finding_ids = [f["id"] for f in findings]
    product_ids = list({f["productId"] for f in findings if f.get("productId")})

    existing = find_assignable_exception(finding_ids)

    if existing:
        exception_id = existing["id"]
        append_findings_to_exception(finding_ids, exception_id)
        action_taken = "added to the existing standing exception"
    else:
        created = create_exception(product_ids, reason)
        exception_id = created["id"]
        append_findings_to_exception(finding_ids, exception_id)
        action_taken = "filed as a new exception"

    exception_url = f"{ARMORCODE_BASE_URL}/#/exceptions/{exception_id}"

    post_pr_comment(
        f"**Exception requested** by @{COMMENT_AUTHOR}\n\n"
        f"- {len(finding_ids)} finding(s) {action_taken}\n"
        f"- Reason: {reason}\n"
        f"- Review and approve here: {exception_url}\n\n"
        f"This does not unblock anything automatically. Security will "
        f"review and approve in ArmorCode."
    )


if __name__ == "__main__":
    try:
        main()
    except requests.HTTPError as e:
        print(f"ArmorCode/GitHub API call failed: {e}", file=sys.stderr)
        print(f"Response body: {e.response.text}", file=sys.stderr)
        sys.exit(1)
