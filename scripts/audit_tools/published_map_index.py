"""Capture published RHCL guide/section IDs and reconcile them with AsciiDoc IDs.

Only evidence metadata is saved, not published page bodies. Matching an ID does
not establish textual equivalence between a source branch and a live page.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from html.parser import HTMLParser
import re
import subprocess
import sys
from urllib.parse import quote, urljoin, urlsplit

from audit_map_migration import (
    ID,
    REF,
    descendants,
    expand,
    file_metadata,
    sha,
    visible_lines,
)


class PageIndex(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = set()
        self.sections = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self.links.add(attrs["href"])
        classes = set((attrs.get("class") or "").split())
        if attrs.get("id") and classes.intersection(
            {"section", "chapter", "preface", "appendix"}
        ):
            self.sections.add(attrs["id"])


def fetch(url):
    # curl uses the system trust store and is accepted by the documentation
    # site's edge service (which rejects Python urllib with HTTP 403).
    result = subprocess.run(
        [
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--max-time",
            "40",
            "--max-filesize",
            "16777216",
            "--write-out",
            "\n%{url_effective}",
            url,
        ],
        capture_output=True,
        timeout=45,
    )
    if result.returncode:
        raise ValueError(result.stderr.decode("utf-8", errors="replace").strip())
    content, _, final_url = result.stdout.rpartition(b"\n")
    final = urlsplit(final_url.decode())
    if final.scheme != "https" or final.netloc != "docs.redhat.com":
        raise ValueError(f"Unexpected publication redirect: {final_url.decode()}")
    return content.decode("utf-8")


def collect(url):
    url = url.rstrip("/")
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "docs.redhat.com"
        or not re.fullmatch(r"/en/documentation/[\w-]+/[\w.-]+", parsed.path)
    ):
        raise ValueError("Use the HTTPS docs.redhat.com product/version landing URL")
    result = {
        "schema_version": 1,
        "url": url,
        "version": parsed.path.rsplit("/", 1)[1],
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "guides": [],
        "errors": [],
    }
    try:
        landing = fetch(url)
        index = PageIndex()
        index.feed(landing)
        result["landing_sha256"] = sha(landing)
        books = set()
        for link in index.links:
            resolved = urlsplit(urljoin(url, link))
            prefix = parsed.path + "/html/"
            if resolved.netloc == parsed.netloc and resolved.path.startswith(prefix):
                book = resolved.path[len(prefix) :].split("/")[0]
                if book:
                    books.add(book)
        if not books:
            raise ValueError(
                "No published guides found; cannot confirm the publication inventory"
            )
    except Exception as error:
        result["errors"].append({"url": url, "error": str(error)})
        return result

    def read_book(book):
        book_url = f"{url}/html-single/{book}/index"
        print(f"Checking published guide: {book}", file=sys.stderr, flush=True)
        try:
            html = fetch(book_url)
            page = PageIndex()
            page.feed(html)
            if not page.sections:
                raise ValueError(
                    "No content section IDs found; page cannot be treated as audited"
                )
            return {
                "url": book_url,
                "book": book,
                "sha256": sha(html),
                "ids": sorted(page.sections),
            }
        except Exception as error:
            return {"url": book_url, "error": str(error)}

    with ThreadPoolExecutor(max_workers=4) as pool:
        for item in pool.map(read_book, sorted(books)):
            if "error" in item:
                result["errors"].append(item)
            else:
                result["guides"].append(item)
    return result


def source_id_patterns(text, attributes, contexts=None):
    """Context may change between assembly and JTBD job; match the stable ID part."""
    attributes = dict(attributes)
    contexts = contexts if contexts is not None else {attributes.get("context", "")}
    contexts = sorted(c for c in contexts if c)
    attributes["context"] = "AUDITCONTEXTTOKEN"
    patterns = []
    for _, line in visible_lines(text):
        if match := ID.match(line):
            value = expand(match[1] or match[2], attributes)
            if REF.search(value):
                continue
            # An unrestricted wildcard also matches generated IDs such as
            # updating-rhcl_14-additional-resources. Only known source contexts
            # are evidence; unknown/renamed contexts stay in the review queue.
            pattern = re.escape(value).replace(
                "AUDITCONTEXTTOKEN",
                "(?:" + "|".join(re.escape(c) for c in contexts) + ")"
                if contexts
                else "(?!)",
            )
            patterns.append(re.compile("^" + pattern + "$"))
    return patterns


def reconcile(index, baseline, maps, sources):
    if index.get("schema_version") != 1 or not isinstance(index.get("guides"), list):
        raise ValueError(
            "Invalid published snapshot; use published-index.json from this audit"
        )
    for guide in index["guides"]:
        if (
            not isinstance(guide, dict)
            or not isinstance(guide.get("url"), str)
            or not isinstance(guide.get("ids"), list)
            or not all(isinstance(identifier, str) for identifier in guide["ids"])
        ):
            raise ValueError(
                "Invalid guide in published snapshot: expected url and a list of section IDs"
            )
    findings, rows = [], []

    def issue(code, message, fix, severity="review", file=""):
        findings.append(
            dict(
                scope="publication",
                severity=severity,
                code=code,
                file=file,
                line=0,
                message=message,
                remediation=fix,
            )
        )

    for error in index.get("errors", []):
        issue(
            "publication-fetch",
            f"{error['url']}: {error['error']}",
            "Retry the publication check; a failed fetch is not evidence of missing content.",
            "error",
        )
    if not index["guides"]:
        issue(
            "publication-empty",
            "No guides were checked.",
            "Capture a complete publication index before claiming coverage.",
            "error",
        )
    # Take attributes from real baseline preprocessing contexts.
    attrs = dict(baseline.attributes)
    for occurrence in baseline.occurrences:
        if occurrence.path.startswith("modules/"):
            attrs.update(occurrence.attributes)
            break
    source_version = attrs.get("version", "")
    if index.get("version") and source_version and index["version"] != source_version:
        issue(
            "release-version",
            f"Source version {source_version}; publication version {index['version']}.",
            "Select a checkout of the 1.4 release source for --source-root.",
            "error",
        )
    # Baseline-only scan is evidence discovery: it can detect a published module
    # omitted from the topic map. Target coverage still uses only reachable maps.
    candidates = {}
    for path in sorted((baseline.root / "modules").rglob("*.adoc")):
        try:
            key = path.resolve().relative_to(baseline.root).as_posix()
        except ValueError:
            continue
        text = path.read_text(encoding="utf-8")
        candidates[key] = {"text": text, "sha256": sha(text), **file_metadata(text)}
    contexts = {
        occurrence.attributes.get("context", "") for occurrence in baseline.occurrences
    }
    patterns = {
        key: source_id_patterns(data["text"], attrs, contexts)
        for key, data in candidates.items()
    }
    nonmodule_patterns = [
        pattern
        for key, data in baseline.files.items()
        if key not in candidates
        for pattern in source_id_patterns(data["text"], attrs, contexts)
    ]
    seen_modules = set()
    for guide in index["guides"]:
        for identifier in guide["ids"]:
            modules = sorted(
                key
                for key, values in patterns.items()
                if any(p.fullmatch(identifier) for p in values)
            )
            matches_other_source = any(
                p.fullmatch(identifier) for p in nonmodule_patterns
            )
            # A new landing concept can copy an assembly's ID. The published
            # assembly heading is not proof that this new module was published.
            if matches_other_source:
                modules = [key for key in modules if key in sources]
            status = (
                "module-matched"
                if modules
                else "assembly-or-snippet-section"
                if matches_other_source
                else "unmatched-section-review"
            )
            if len(modules) > 1:
                status = "ambiguous-source-id-review"
            url = guide["url"] + "#" + quote(identifier, safe="_-.")
            rows.append(
                {"id": identifier, "url": url, "modules": modules, "status": status}
            )
            for key in modules:
                seen_modules.add(key)
                if key not in sources:
                    sources.setdefault(key, set()).add(
                        "[published topic outside selected topic-map assemblies]"
                    )
                    baseline.files[key] = candidates[key]
                    for node in descendants(baseline.walk(key, attrs)):
                        if node.path.startswith(
                            ("modules/", "snippets/")
                        ) and node.path.endswith(".adoc"):
                            sources.setdefault(node.path, set()).add(
                                f"[published module: {key}]"
                            )
                    issue(
                        "published-module-outside-topic-map",
                        f"{key} matches {url}",
                        "Reconcile the release topic map with the live guide; include this published module in a reachable migration job.",
                        file=key,
                    )
    unresolved = sum(row["status"] == "unmatched-section-review" for row in rows)
    ambiguous = sum(row["status"] == "ambiguous-source-id-review" for row in rows)
    if unresolved:
        issue(
            "unmatched-published-sections",
            f"{unresolved} published sections have no explicit source ID match.",
            "Review unmatched rows in published-sections.csv: these can be assembly prose, generated IDs, renamed topics, or content absent from the release source.",
        )
    if ambiguous:
        issue(
            "ambiguous-published-sections",
            f"{ambiguous} published IDs match multiple modules.",
            "Resolve the source identity before claiming those modules have been verified against publication.",
        )
    unconfirmed = sorted(
        key for key in sources if key.startswith("modules/") and key not in seen_modules
    )
    if unconfirmed:
        issue(
            "source-not-confirmed-published",
            f"{len(unconfirmed)} source modules have no published ID evidence.",
            "Review unconfirmed rows in coverage.csv; the release branch can contain unpublished changes. Do not silently remove them from the migration inventory.",
        )
    return rows, findings
