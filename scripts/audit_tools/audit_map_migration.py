#!/usr/bin/env python3
"""Audit a reachable MAP hierarchy against a separate published-release source.

Requires Python 3.10+ and PyYAML. Read-only except for the requested report folder.
No map-tools dependency; no implicit Git fetch, checkout, or source modifications.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    raise SystemExit(
        "Install PyYAML in your Python environment: python3 -m pip install PyYAML"
    )

INCLUDE = re.compile(r"^\s*include::([^\[]+)\[(.*)\]\s*$")
ATTRIBUTE = re.compile(r"^:(!?[\w.-]+!?):(?:\s+(.*))?$")
REF = re.compile(r"\{([\w.-]+)\}")
HEADING = re.compile(r"^(=+)\s+(.+)$")
ID = re.compile(
    r"^\s*(?:\[id=[\"\x27]([^\"\x27]+)[\"\x27]\]|\[\[([^\],]+)(?:,[^\]]*)?\]\])\s*$"
)
CONTENT_TYPE = re.compile(r"^:(?:_mod-docs-content-type|_content-type):\s*(\w+)", re.M)
RULE_COMMIT = "6cd4e1a4c78c95fb3496e62f4f5d8d4fd6a7fb76"
RULE_BASE = f"https://gitlab.cee.redhat.com/ccs-ai/ccs-ai-agentic-workflow/-/blob/{RULE_COMMIT}/plugins/jtbd-tools/reference/"


def expand(value, attributes):
    for _ in range(12):
        updated = REF.sub(lambda m: attributes.get(m[1], m[0]), value)
        if updated == value:
            break
        value = updated
    return value


def visible_lines(text):
    """Remove line and block comments, keeping original line numbers."""
    comment = False
    for number, line in enumerate(text.splitlines(), 1):
        if line.strip() == "////":
            comment = not comment
        elif not comment and not line.lstrip().startswith("//"):
            yield number, line


def primary_id(text):
    for _, line in visible_lines(text):
        if HEADING.match(line):
            break
        if match := ID.match(line):
            return match[1] or match[2]
    return ""


def file_metadata(text):
    lines = list(visible_lines(text))
    headings = [(n, m[1], m[2]) for n, s in lines if (m := HEADING.match(s))]
    kind = CONTENT_TYPE.search("\n".join(s for _, s in lines))
    return {
        "kind": kind[1].upper() if kind else "UNKNOWN",
        "title": headings[0][2] if headings else "",
        "heading_line": headings[0][0] if headings else 0,
        "headings": headings,
        "primary_id": primary_id(text),
    }


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def git_info(root):
    def git(*args):
        p = subprocess.run(
            ["git", "-C", str(root), *args], capture_output=True, text=True
        )
        return p.stdout.strip() if p.returncode == 0 else "unknown"

    return {
        "root": str(root),
        "commit": git("rev-parse", "HEAD"),
        "branch": git("branch", "--show-current"),
        "status": git("status", "--porcelain"),
    }


def topic_entries(path, distro):
    """OpenShift topic-map YAML: documents/lists, nested Dir/Topics, inherited Distros."""
    result = []

    def visit(node, directory=Path(), enabled=True, group=""):
        if isinstance(node, list):
            for child in node:
                visit(child, directory, enabled, group)
            return
        if not isinstance(node, dict):
            raise ValueError("Topic-map entries must be mappings or lists")
        if "Distros" in node:
            distros = node["Distros"]
            if isinstance(distros, str):
                distros = [s.strip() for s in distros.split(",")]
            if not isinstance(distros, list):
                raise ValueError("Distros must be a comma-separated string or list")
            enabled = enabled and (distro in distros or "all" in distros)
        if not enabled:
            return
        directory = directory / node.get("Dir", "")
        group = group or node.get("Name", "")
        if "File" in node:
            filename = str(node["File"])
            if not filename.endswith(".adoc"):
                filename += ".adoc"
            assembly = directory / filename
            if assembly.is_absolute() or ".." in assembly.parts:
                raise ValueError(
                    f"Topic-map path must stay within the release source: {assembly}"
                )
            result.append(
                {
                    "assembly": assembly.as_posix(),
                    "title": node.get("Name", ""),
                    "guide": group,
                }
            )
        if "Topics" in node:
            visit(node["Topics"], directory, enabled, group)
        elif "File" not in node:
            raise ValueError(
                f"Unsupported topic-map entry: expected File or Topics, got {list(node)}"
            )

    for document in yaml.safe_load_all(path.read_text()):
        if document is not None:
            visit(document)
    if not result:
        raise ValueError(f"No assemblies selected for distro {distro!r} in {path}")
    return result


@dataclass
class Occurrence:
    path: str
    source: str
    line: int
    options: str
    attributes: dict
    offset: int
    children: list = field(default_factory=list)


class Graph:
    """Conservative include walk; unsupported preprocessing is a blocking finding."""

    def __init__(self, root, label, attributes):
        self.root = root.resolve()
        self.label = label
        self.attributes = attributes
        self.files = {}
        self.occurrences = []
        self.issues = []

    def issue(self, code, path, line, message, fix, severity="error"):
        item = dict(
            scope=self.label,
            severity=severity,
            code=code,
            file=path,
            line=line,
            message=message,
            remediation=fix,
        )
        if item not in self.issues:
            self.issues.append(item)

    def relative(self, path):
        return path.resolve().relative_to(self.root).as_posix()

    def resolve(self, source, target):
        if (
            Path(target).is_absolute()
            or re.match(r"\w+://", target)
            or REF.search(target)
        ):
            raise ValueError("Absolute, remote, or unresolved attribute-based include")
        local = self.root / source.parent / target
        # This repo uses directory symlinks; root-based includes are also used in
        # assembly sources. An existing local path always takes precedence.
        if local.is_file():
            candidate = local
        elif target.split("/", 1)[0] in {
            "modules",
            "assemblies",
            "maps",
            "snippets",
            "_attributes",
            "_artifacts",
        }:
            candidate = self.root / target
        else:
            candidate = local
        try:
            return candidate.resolve().relative_to(self.root)
        except ValueError:
            raise ValueError("Include escapes the selected repository root") from None

    def walk(self, entry, attributes=None):
        return self._walk(
            Path(entry),
            dict(self.attributes if attributes is None else attributes),
            (),
            "",
            0,
            "",
            0,
        )

    def _walk(self, path, attrs, stack, source, line, options, offset):
        try:
            key = self.relative(self.root / path)
        except ValueError:
            self.issue(
                "outside-root",
                source,
                line,
                str(path),
                "Keep includes within the selected source tree.",
            )
            return None
        if key in stack:
            self.issue(
                "include-cycle",
                source,
                line,
                " -> ".join((*stack, key)),
                "Remove the recursive include.",
            )
            return None
        absolute = self.root / key
        if not absolute.is_file():
            self.issue(
                "missing-include",
                source or key,
                line,
                f"Missing {key}",
                "Correct the include path or restore the file. A file on disk is not covered until a reachable map includes it.",
            )
            return None
        if key not in self.files:
            text = absolute.read_text(encoding="utf-8")
            self.files[key] = {"text": text, "sha256": sha(text), **file_metadata(text)}
        node = Occurrence(key, source, line, options, dict(attrs), offset)
        self.occurrences.append(node)
        active = [True]
        literal = None
        for number, raw in visible_lines(self.files[key]["text"]):
            value = raw.strip()
            # Includes in literal blocks are still processed by Asciidoctor;
            # attribute-looking lines inside those blocks are not declarations.
            if value in {"----", "....", "++++"}:
                literal = (
                    None if literal == value else value if literal is None else literal
                )
                continue
            conditional = re.match(r"^(ifdef|ifndef)::([^\[]+)\[(.*)\]$", value)
            if conditional:
                mode, names, inline = conditional.groups()
                if "," in names and "+" in names:
                    self.issue(
                        "unsupported-condition",
                        key,
                        number,
                        value,
                        "Resolve this condition with Asciidoctor before auditing.",
                    )
                present = (
                    all(n.strip() in attrs for n in names.split("+"))
                    if "+" in names
                    else any(n.strip() in attrs for n in names.split(","))
                )
                enabled = present if mode == "ifdef" else not present
                if not inline:
                    active.append(active[-1] and enabled)
                    continue
                if not (active[-1] and enabled):
                    continue
                value = inline
            elif value.startswith("ifeval::"):
                self.issue(
                    "unsupported-condition",
                    key,
                    number,
                    value,
                    "Evaluate ifeval with the build attributes; this audit cannot certify this subtree.",
                )
                active.append(False)
                continue
            elif value.startswith("endif::"):
                if len(active) == 1:
                    self.issue(
                        "unbalanced-condition",
                        key,
                        number,
                        value,
                        "Balance ifdef/ifndef/endif within the file.",
                    )
                else:
                    active.pop()
                continue
            if not active[-1]:
                continue
            if not literal and (m := ATTRIBUTE.match(value)):
                name, content = m.groups()
                if name.startswith("!") or name.endswith("!"):
                    attrs.pop(name.strip("!"), None)
                else:
                    attrs[name] = expand(content or "", attrs)
                continue
            m = INCLUDE.match(value)
            if not m:
                if value.startswith("include::"):
                    self.issue(
                        "malformed-include",
                        key,
                        number,
                        value,
                        "Use include::path[options] on its own line.",
                    )
                continue
            target, child_options = m.groups()
            target = expand(target.strip(), attrs)
            child_options = expand(child_options, attrs)
            if REF.search(child_options):
                self.issue(
                    "unresolved-include-options",
                    key,
                    number,
                    value,
                    "Supply the attributes used in include options before claiming coverage.",
                )
                continue
            if "leveloffset=" in child_options and not re.search(
                r'(?:^|,)\s*leveloffset\s*=\s*["\x27]?[+-]?\d+["\x27]?(?:\s*,|\s*$)',
                child_options,
            ):
                self.issue(
                    "unsupported-leveloffset",
                    key,
                    number,
                    value,
                    "Use a numeric relative or absolute leveloffset, then rerun the hierarchy check.",
                )
            if re.search(r"(?:^|,)\s*(?:tags?|lines)\s*=", child_options):
                self.issue(
                    "partial-include",
                    key,
                    number,
                    value,
                    "Check the selected lines/tags with Asciidoctor. Whole-file coverage is not established by a partial include.",
                )
                continue
            try:
                child_path = self.resolve(Path(key), target)
            except ValueError as error:
                self.issue(
                    "unresolved-include",
                    key,
                    number,
                    f"{value}: {error}",
                    "Supply the missing attribute with --attribute NAME=VALUE, or correct the include.",
                )
                continue
            child_offset = offset
            if level := re.search(
                r'(?:^|,)\s*leveloffset\s*=\s*["\x27]?([+-]?\d+)', child_options
            ):
                child_offset = (
                    offset + int(level[1])
                    if level[1].startswith(("+", "-"))
                    else int(level[1])
                )
            child = self._walk(
                child_path,
                attrs,
                (*stack, key),
                key,
                number,
                child_options,
                child_offset,
            )
            if child:
                node.children.append(child)
        if len(active) != 1:
            self.issue(
                "unbalanced-condition",
                key,
                0,
                "Unclosed conditional",
                "Balance ifdef/ifndef/endif within the file.",
            )
        return node

    def modules(self):
        return {
            path
            for path in self.files
            if path.startswith("modules/") and path.endswith(".adoc")
        }


def descendants(node):
    if node:
        yield node
        for child in node.children:
            yield from descendants(child)


def content_children(node, graph):
    return [
        c
        for c in node.children
        if graph.files[c.path]["kind"] != "ATTRIBUTES"
        and not c.path.startswith(("_attributes/", "_artifacts/"))
    ]


def duplicate_job_include_rows(graph):
    """Return job files that occur more than once in the reachable map graph."""
    occurrences = defaultdict(list)
    for occurrence in graph.occurrences:
        if occurrence.path.startswith("maps/jobs/") and occurrence.path.endswith(
            ".adoc"
        ):
            occurrences[occurrence.path].append(occurrence)
    return [
        {
            "job": path,
            "occurrences": len(nodes),
            "include_sites": [
                f"{node.source or '<entry>'}:{node.line}" for node in nodes
            ],
            "status": "duplicate-job-include",
        }
        for path, nodes in sorted(occurrences.items())
        if len(nodes) > 1
    ]


def job_paths(navigation, graph):
    """Map each reachable file to the JTBD jobs that contain it."""
    paths = defaultdict(set)
    for category in content_children(navigation, graph) if navigation else []:
        for job in content_children(category, graph):
            for node in descendants(job):
                paths[node.path].add(job.path)
    return paths


def duplicate_module_inclusion_rows(graph_paths):
    """Return modules included by more than one reachable JTBD job."""
    return [
        {
            "module": module,
            "job_count": len(jobs),
            "jobs": sorted(jobs),
            "status": "duplicate-module-across-jobs",
        }
        for module, jobs in sorted(graph_paths.items())
        if module.startswith("modules/") and len(jobs) > 1
    ]


def cross_distro_entries(root, configured=None):
    """Resolve explicit DISTRO=PATH entries or discover maps/*/navigation.adoc."""
    entries = []
    if configured:
        for value in configured:
            distro, separator, entry = value.partition("=")
            if not separator or not distro or not entry:
                raise ValueError(
                    "--cross-distro-entry must use DISTRO=maps/PATH/navigation.adoc"
                )
            entries.append({"distro": distro, "entry": entry})
    else:
        entries = [
            {
                "distro": navigation.parent.name,
                "entry": navigation.relative_to(root).as_posix(),
            }
            for navigation in sorted((root / "maps").glob("*/navigation.adoc"))
        ]
    unique = []
    seen = set()
    for item in entries:
        distro, entry = item["distro"], Path(item["entry"])
        if not re.fullmatch(r"[\w.-]+", distro):
            raise ValueError(f"Invalid cross-distro name: {distro}")
        if (
            entry.is_absolute()
            or not entry.parts
            or entry.parts[0] != "maps"
            or ".." in entry.parts
        ):
            raise ValueError(
                "Cross-distro entries must be paths inside maps/, relative to --repo-root"
            )
        if not (root / entry).is_file():
            raise ValueError(f"Cross-distro entry does not exist: {entry}")
        key = (distro, entry.as_posix())
        if key not in seen:
            seen.add(key)
            unique.append({"distro": distro, "entry": entry.as_posix()})
    if not unique:
        raise ValueError("No maps/*/navigation.adoc entries found for cross-distro audit")
    return unique


def _inventory_record(records, path, data):
    return records.setdefault(
        path,
        {
            "path": path,
            "primary_id": data["primary_id"],
            "sha256": data["sha256"],
            "titles": set(),
            "distros": set(),
            "categories": set(),
            "contexts": set(),
            "entries": set(),
            "include_sites": set(),
            "usage_count": 0,
        },
    )


def _identity_conflicts(records, entity_type, check_titles=False):
    conflicts = []

    def add_groups(field, conflict_same, conflict_different=None):
        groups = defaultdict(set)
        for path, record in records.items():
            value = record[field]
            if value:
                groups[value].add(path)
        for identity, paths in sorted(groups.items()):
            if len(paths) < 2:
                continue
            hashes = {records[path]["sha256"] for path in paths}
            conflict = (
                conflict_different
                if conflict_different and len(hashes) > 1
                else conflict_same
            )
            severity = "error" if conflict == "same-id-different-content" else "review"
            conflicts.append(
                {
                    "entity_type": entity_type,
                    "conflict": conflict,
                    "identity": identity,
                    "paths": sorted(paths),
                    "distros": sorted(
                        set().union(*(records[path]["distros"] for path in paths))
                    ),
                    "severity": severity,
                    "remediation": (
                        "Assign unique IDs or consolidate the conflicting sources."
                        if severity == "error"
                        else "Choose one canonical source path or document why separate aliases are required."
                    ),
                }
            )

    add_groups("primary_id", "same-id-same-content", "same-id-different-content")
    add_groups("sha256", "same-content-different-path")
    if check_titles:
        title_groups = defaultdict(set)
        title_labels = {}
        for path, record in records.items():
            for title in record["titles"]:
                key = title.casefold()
                if key:
                    title_groups[key].add(path)
                    title_labels.setdefault(key, title)
        for key, paths in sorted(title_groups.items()):
            if len(paths) < 2 or len({records[p]["sha256"] for p in paths}) < 2:
                continue
            conflicts.append(
                {
                    "entity_type": entity_type,
                    "conflict": "same-title-different-content",
                    "identity": title_labels[key],
                    "paths": sorted(paths),
                    "distros": sorted(
                        set().union(*(records[path]["distros"] for path in paths))
                    ),
                    "severity": "review",
                    "remediation": "Confirm that these are distinct outcomes; do not merge them from title similarity alone.",
                }
            )
    return conflicts


def cross_distro_inventory(root, entries, base_attributes):
    """Build one deterministic job/module registry across navigation entries."""
    jobs, modules = {}, {}
    issues = []
    include_graph = {}
    for spec in entries:
        distro, entry = spec["distro"], spec["entry"]
        attributes = dict(base_attributes)
        attributes[distro] = ""
        graph = Graph(root, f"cross-distro:{distro}", attributes)
        navigation = graph.walk(entry)
        issues.extend(graph.issues)
        include_graph[f"{distro}:{entry}"] = [
            {
                "source": node.source,
                "line": node.line,
                "target": node.path,
                "options": node.options,
                "offset": node.offset,
            }
            for node in graph.occurrences
            if node.source
        ]
        if not navigation:
            continue
        for category in content_children(navigation, graph):
            category_title = title_for(category, graph)
            context = f"{distro}:{category_title}"
            for job in content_children(category, graph):
                job_data = graph.files[job.path]
                record = _inventory_record(jobs, job.path, job_data)
                record["titles"].add(title_for(job, graph))
                record["distros"].add(distro)
                record["categories"].add(category_title)
                record["contexts"].add(context)
                record["entries"].add(entry)
                record["include_sites"].add(f"{distro}:{job.source}:{job.line}")
                record["usage_count"] += 1
                record.setdefault("modules", set())
                for node in descendants(job):
                    if not (
                        node.path.startswith("modules/")
                        and node.path.endswith(".adoc")
                    ):
                        continue
                    record["modules"].add(node.path)
                    module_data = graph.files[node.path]
                    module = _inventory_record(modules, node.path, module_data)
                    module["titles"].add(
                        expand(module_data["title"], node.attributes)
                    )
                    module["distros"].add(distro)
                    module["categories"].add(category_title)
                    module["contexts"].add(context)
                    module["entries"].add(entry)
                    module["include_sites"].add(
                        f"{distro}:{node.source}:{node.line}"
                    )
                    module["usage_count"] += 1
                    module.setdefault("jobs", set()).add(job.path)

    job_rows = [
        {
            "job": path,
            "primary_id": record["primary_id"],
            "titles": sorted(record["titles"]),
            "sha256": record["sha256"],
            "distros": sorted(record["distros"]),
            "distro_count": len(record["distros"]),
            "categories": sorted(record["categories"]),
            "contexts": sorted(record["contexts"]),
            "entries": sorted(record["entries"]),
            "include_sites": sorted(record["include_sites"]),
            "usage_count": record["usage_count"],
            "modules": sorted(record.get("modules", set())),
            "module_count": len(record.get("modules", set())),
        }
        for path, record in sorted(jobs.items())
    ]
    module_rows = [
        {
            "module": path,
            "primary_id": record["primary_id"],
            "titles": sorted(record["titles"]),
            "sha256": record["sha256"],
            "distros": sorted(record["distros"]),
            "distro_count": len(record["distros"]),
            "categories": sorted(record["categories"]),
            "contexts": sorted(record["contexts"]),
            "entries": sorted(record["entries"]),
            "include_sites": sorted(record["include_sites"]),
            "usage_count": record["usage_count"],
            "jobs": sorted(record.get("jobs", set())),
            "job_count": len(record.get("jobs", set())),
        }
        for path, record in sorted(modules.items())
    ]
    overlaps = [
        {
            "entity_type": entity_type,
            "path": row[entity_type],
            "distro_count": row["distro_count"],
            "distros": row["distros"],
            "contexts": row["contexts"],
            "related_jobs": row.get("jobs", []),
        }
        for entity_type, rows in (("job", job_rows), ("module", module_rows))
        for row in rows
        if row["distro_count"] > 1
    ]
    conflicts = _identity_conflicts(jobs, "job", check_titles=True)
    conflicts.extend(_identity_conflicts(modules, "module"))
    conflict_findings = [
        {
            "scope": "cross-distro",
            "severity": row["severity"],
            "code": f"cross-distro-{row['conflict']}",
            "file": row["paths"][0],
            "line": 1,
            "message": (
                f"{row['entity_type'].title()} identity {row['identity']!r} "
                f"matches: {', '.join(row['paths'])}."
            ),
            "remediation": row["remediation"],
        }
        for row in conflicts
    ]
    return {
        "entries": entries,
        "summary": {
            "cross_distro_entries": len(entries),
            "cross_distro_jobs": len(job_rows),
            "cross_distro_modules": len(module_rows),
            "cross_distro_shared_jobs": sum(
                row["distro_count"] > 1 for row in job_rows
            ),
            "cross_distro_shared_modules": sum(
                row["distro_count"] > 1 for row in module_rows
            ),
            "cross_distro_identity_conflicts": len(conflicts),
        },
        "jobs": job_rows,
        "modules": module_rows,
        "overlap": overlaps,
        "identity_conflicts": conflicts,
        "issues": issues,
        "include_graph": include_graph,
    }, issues + conflict_findings


def title_for(node, graph):
    title = graph.files[node.path]["title"]
    owner = node
    if not title:
        for child in content_children(node, graph):
            if graph.files[child.path]["title"]:
                title = graph.files[child.path]["title"]
                owner = child
                break
    if nav := re.search(r'(?:^|,)\s*navtitle="([^"]+)"', node.options):
        title = nav[1]
    return expand(title, owner.attributes)


def jtbd_audit(graph, navigation):
    findings, jobs, categories = [], [], []

    def add(code, node, message, fix, severity="error", reference="toc-guidelines.md"):
        findings.append(
            dict(
                scope="jtbd",
                severity=severity,
                code=code,
                file=node.path,
                line=graph.files[node.path]["heading_line"] or 1,
                message=message,
                remediation=fix,
                rule_source=RULE_BASE + reference,
            )
        )

    if not navigation:
        return findings, jobs, categories
    if graph.files[navigation.path]["kind"] != "MAP":
        add(
            "navigation-type",
            navigation,
            "Navigation is not marked MAP.",
            "Set :_mod-docs-content-type: MAP.",
        )
    title_uses = defaultdict(list)
    for category in content_children(navigation, graph):
        cat_title = title_for(category, graph)
        child_jobs = content_children(category, graph)
        categories.append(
            {"category": cat_title, "file": category.path, "jobs": len(child_jobs)}
        )
        if graph.files[category.path]["kind"] != "MAP":
            add(
                "category-type",
                category,
                "Category is not marked MAP.",
                "Use a MAP for this organizational node.",
            )
        # Category nodes organize content; substantive prose needs a job/topic.
        prose = [
            s
            for _, s in visible_lines(graph.files[category.path]["text"])
            if s.strip()
            and not s.lstrip().startswith(
                (":", "=", "[", "include::", "ifdef::", "ifndef::", "endif::")
            )
        ]
        if prose:
            add(
                "category-content",
                category,
                "Category has content beyond its heading and includes.",
                "Move explanatory content into a job parent topic.",
                "review",
            )
        for job in child_jobs:
            children = content_children(job, graph)
            title = title_for(job, graph)
            title_uses[title.casefold()].append(job)
            landing = children[0] if children else None
            has_parent = bool(
                landing
                and graph.files[landing.path]["kind"] == "CONCEPT"
                and landing.offset == job.offset
            )
            # Some existing job files are titled wrappers with a +1 child concept;
            # these need review because the concept is a child, not the parent.
            if not has_parent:
                collection = cat_title.casefold().replace("’", "'") in {
                    "reference",
                    "what's new",
                }
                add(
                    "parent-concept",
                    job,
                    "No first CONCEPT at the job's own heading level.",
                    "If this is a task, nest it under its main job. For a genuine main job, add/reuse a parent concept at leveloffset=+0 with what/why/how. Review whether reference/release-note collections represent jobs at all.",
                    severity="review" if collection else "error",
                    reference="methodology.md",
                )
            elif len(graph.files[landing.path]["headings"]) > 1:
                add(
                    "parent-subheadings",
                    landing,
                    "Parent concept contains additional headings.",
                    "Keep one title in the landing concept and move detailed sections into child topics.",
                    reference="pitfalls.md",
                )
            if not title:
                add(
                    "job-title",
                    job,
                    "No title could be resolved for the job.",
                    "Provide a titled parent concept.",
                )
            reachable = list(descendants(job))
            procedures = [
                n
                for n in reachable
                if graph.files[n.path]["kind"] in {"PROCEDURE", "TASK"}
            ]
            if re.match(
                r"^(About|Understanding|Describing|Introduction|Explanation|Overview of)\b",
                title,
                re.I,
            ):
                add(
                    "redundant-title-prefix",
                    job,
                    title,
                    "Use a descriptive outcome or noun phrase without the redundant prefix.",
                    reference="consistency-guidelines.md",
                )
            if re.match(
                r"^(For (administrators?|developers?|operators?)|Get started as)\b",
                title,
                re.I,
            ):
                add(
                    "persona-gated-job",
                    job,
                    title,
                    "Organize by the outcome or approach; record personas as planning metadata.",
                    reference="consistency-guidelines.md",
                )
            if re.match(r"^(Verify|Validate|Check|Test|Confirm)\b", title, re.I):
                add(
                    "verification-job",
                    job,
                    title,
                    "Review whether this belongs as the final verification step of its execution job.",
                    "review",
                )
            for node in reachable:
                data = graph.files[node.path]
                if data["headings"]:
                    # Root and category are excluded; this is a conservative
                    # source heading check, not a DITA chunking simulation.
                    level = len(data["headings"][0][1]) + node.offset - 2
                    if (
                        level > 3
                        and 'toc="no"' not in node.options
                        and "toc=no" not in node.options
                    ):
                        add(
                            "navigation-depth",
                            node,
                            f"Projected level {level} below category (maximum 3).",
                            "Reduce nesting/leveloffset; verify the resulting navigation in the preview.",
                        )
                node_title = expand(data["title"], node.attributes)
                procedural = data["kind"] in {"PROCEDURE", "TASK"} or (
                    node is landing and procedures
                )
                if procedural and re.match(
                    r"^(Configuring|Installing|Managing|Creating|Using|Deploying|Updating|Monitoring|Setting|Enabling|Verifying|Publishing)\b",
                    node_title,
                    re.I,
                ):
                    add(
                        "gerund-title",
                        node,
                        node_title,
                        "Use an imperative title for procedures and jobs containing procedures.",
                        reference="consistency-guidelines.md",
                    )
            jobs.append(
                {
                    "category": cat_title,
                    "job": job.path,
                    "title": title,
                    "parent": landing.path if has_parent else "",
                    "procedures": len(procedures),
                    "module_count": len(
                        {n.path for n in reachable if n.path.startswith("modules/")}
                    ),
                    "review_status": "required",
                    "editorial_review": "Confirm a real user outcome (Why/How test); parent explains what/why/how; themed approaches; prerequisites and links; noun phrase for concept/reference-only jobs or imperative with procedures; no redundant overview; no duplicated content.",
                }
            )
    if not any(c["category"].casefold() == "discover" for c in categories):
        add(
            "discover-required",
            navigation,
            "No Discover category found.",
            "Include the required Discover use case.",
            reference="consistency-guidelines.md",
        )
    for title, nodes in title_uses.items():
        if title and len(nodes) > 1:
            for node in nodes:
                add(
                    "duplicate-job-title",
                    node,
                    f"Title appears {len(nodes)} times: {title}",
                    "Consolidate duplicate jobs or give distinct outcomes unique titles.",
                    reference="consistency-guidelines.md",
                )
    return findings, jobs, categories


def write_csv(path, rows, fields):
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    k: "; ".join(str(v) for v in value)
                    if isinstance(value, list)
                    else value
                    for k, value in row.items()
                }
            )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="Repository containing the maps being migrated",
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        required=True,
        help="Separate checkout of the published release source (1.4)",
    )
    parser.add_argument(
        "--topic-map",
        default="_topic_maps/_topic_map.yml",
        help="YAML inventory relative to source root; accepts any filename with OpenShift Dir/Topics/File schema",
    )
    parser.add_argument(
        "--entry",
        default="maps/rhcl/navigation.adoc",
        help="Migration entry relative to repo root",
    )
    parser.add_argument("--distro", default="rhcl")
    parser.add_argument(
        "--attribute", action="append", default=[], metavar="NAME[=VALUE]"
    )
    parser.add_argument(
        "--published-url",
        help="Fetch guide/topic IDs from this published product/version page",
    )
    parser.add_argument(
        "--published-snapshot", type=Path, help="Reuse published-index.json offline"
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--strict-review",
        action="store_true",
        help="Also exit 1 when editorial/reconciliation review remains",
    )
    parser.add_argument(
        "--cross-distro-audit",
        action="store_true",
        help="Also build a deterministic job/module inventory across navigation maps",
    )
    parser.add_argument(
        "--cross-distro-entry",
        action="append",
        default=[],
        metavar="DISTRO=PATH",
        help="Navigation entry for cross-distro audit; repeat as needed. Defaults to maps/*/navigation.adoc",
    )
    args = parser.parse_args(argv)
    if args.published_url and args.published_snapshot:
        parser.error("Choose --published-url or --published-snapshot")
    target, source = args.repo_root.resolve(), args.source_root.resolve()
    base_attrs = {"nbsp": " "}
    for item in args.attribute:
        name, _, value = item.partition("=")
        base_attrs[name] = value
    attrs = dict(base_attrs)
    attrs[args.distro] = ""
    try:
        entries = topic_entries(source / args.topic_map, args.distro)
        if (
            Path(args.entry).is_absolute()
            or not Path(args.entry).parts
            or Path(args.entry).parts[0] != "maps"
            or ".." in Path(args.entry).parts
        ):
            raise ValueError(
                "--entry must be a path inside maps/, relative to --repo-root"
            )
        baseline = Graph(source, "release-source", attrs)
        sources = defaultdict(set)
        assembly_reviews = []
        for entry in entries:
            root = baseline.walk(entry["assembly"])
            for node in descendants(root):
                if node.path.startswith(
                    ("modules/", "snippets/")
                ) and node.path.endswith(".adoc"):
                    sources[node.path].add(entry["assembly"])
            assembly_reviews.append(
                {
                    **entry,
                    "review_status": "required",
                    "remediation": "Check assembly-only prose, prerequisites, additional resources and media are retained in the appropriate jobs; module inclusion alone does not prove this.",
                }
            )
        maps = Graph(target, "maps", attrs)
        navigation = maps.walk(args.entry)
        findings = baseline.issues + maps.issues
        if not sources:
            findings.append(
                dict(
                    scope="release-source",
                    severity="error",
                    code="empty-module-inventory",
                    file=args.topic_map,
                    line=0,
                    message="No module or snippet files were reached from the selected assemblies.",
                    remediation="Verify the topic map, selected distro, source root and include conventions before comparing coverage.",
                )
            )
        jtbd_findings, jobs, categories = jtbd_audit(maps, navigation)
        findings.extend(jtbd_findings)
        duplicate_job_includes = duplicate_job_include_rows(maps)
        for row in duplicate_job_includes:
            findings.append(
                {
                    "scope": "maps",
                    "severity": "error",
                    "code": "duplicate-job-include",
                    "file": row["job"],
                    "line": 0,
                    "message": (
                        f"Job file is included {row['occurrences']} times at "
                        f"{', '.join(row['include_sites'])}."
                    ),
                    "remediation": "Keep each job in one reachable navigation location, or verify and document why repeated inclusion is required.",
                }
            )
        graph_paths = job_paths(navigation, maps)
        duplicate_module_inclusions = duplicate_module_inclusion_rows(graph_paths)
        for row in duplicate_module_inclusions:
            findings.append(
                {
                    "scope": "maps",
                    "severity": "review",
                    "code": "duplicate-module-across-jobs",
                    "file": row["module"],
                    "line": maps.files[row["module"]]["heading_line"] or 1,
                    "message": (
                        f"Module is included by {row['job_count']} jobs: "
                        f"{', '.join(row['jobs'])}."
                    ),
                    "remediation": "Confirm that the module is intentionally shared. Otherwise keep it under one job and link to it from the other job.",
                    "rule_source": RULE_BASE + "pitfalls.md",
                }
            )
        cross_report = None
        if args.cross_distro_audit:
            cross_entries = cross_distro_entries(target, args.cross_distro_entry)
            cross_report, cross_findings = cross_distro_inventory(
                target, cross_entries, base_attrs
            )
            finding_keys = {
                (
                    finding.get("code"),
                    finding.get("file"),
                    finding.get("line"),
                    finding.get("message"),
                )
                for finding in findings
            }
            for finding in cross_findings:
                key = (
                    finding.get("code"),
                    finding.get("file"),
                    finding.get("line"),
                    finding.get("message"),
                )
                if key not in finding_keys:
                    findings.append(finding)
                    finding_keys.add(key)
        publication = None
        published_rows = []
        if args.published_url or args.published_snapshot:
            from published_map_index import collect, reconcile

            publication = (
                collect(args.published_url)
                if args.published_url
                else json.loads(args.published_snapshot.read_text())
            )
            published_rows, pub_findings = reconcile(
                publication, baseline, maps, sources
            )
            findings.extend(pub_findings)
            findings.extend(issue for issue in baseline.issues if issue not in findings)
        by_module = defaultdict(list)
        for row in published_rows:
            for module in row["modules"]:
                by_module[module].append(row["url"])
        coverage = []
        for module, assemblies in sorted(sources.items()):
            original = baseline.files.get(module)
            current = maps.files.get(module)
            if current:
                status = (
                    "covered-identical"
                    if original and original["sha256"] == current["sha256"]
                    else "covered-changed"
                )
            else:
                status = "missing"
            candidates = []
            if not current and original:
                candidates = [
                    p
                    for p, data in maps.files.items()
                    if p.startswith("modules/")
                    and (
                        data["sha256"] == original["sha256"]
                        or (
                            original["primary_id"]
                            and data["primary_id"] == original["primary_id"]
                        )
                    )
                ]
            coverage.append(
                {
                    "module": module,
                    "status": status,
                    "assemblies": sorted(assemblies),
                    "map_jobs": sorted(graph_paths[module]),
                    "replacement_candidates": sorted(candidates),
                    "publication": "confirmed-topic-id"
                    if by_module[module]
                    else "unconfirmed"
                    if publication
                    else "not-checked",
                    "published_urls": sorted(set(by_module[module])),
                    "release_sha256": original["sha256"] if original else "",
                    "map_sha256": current["sha256"] if current else "",
                    "remediation": "Add an include under the appropriate reachable job, or document and verify a replacement."
                    if not current
                    else "Review source differences; inclusion does not prove preservation of the 1.4 content."
                    if status == "covered-changed"
                    else "",
                }
            )
        extras = [
            {
                "module": path,
                "map_jobs": sorted(graph_paths[path]),
                "status": "additional-map-content",
            }
            for path in sorted(maps.modules() - sources.keys())
        ]
        unreachable = [
            {"file": path.relative_to(target).as_posix(), "status": "unreachable-job"}
            for path in sorted((target / "maps/jobs").glob("*.adoc"))
            if maps.relative(path) not in maps.files
        ]
        counts = Counter(r["status"] for r in coverage)
        errors = sum(f["severity"] == "error" for f in findings)
        review = (
            len(jobs)
            + len(assembly_reviews)
            + counts["covered-changed"]
            + len(duplicate_job_includes)
            + sum(f["severity"] == "review" for f in findings)
        )
        summary = {
            "assemblies": len(entries),
            "required_files": len(coverage),
            "required_modules": sum(
                r["module"].startswith("modules/") for r in coverage
            ),
            "covered_identical": counts["covered-identical"],
            "covered_changed": counts["covered-changed"],
            "missing": counts["missing"],
            "additional_map_modules": len(extras),
            "reachable_jobs": len(jobs),
            "unreachable_jobs": len(unreachable),
            "duplicate_job_includes": len(duplicate_job_includes),
            "duplicate_modules_across_jobs": len(duplicate_module_inclusions),
            "errors": errors,
            "review_items": review,
            "published_guides_checked": len(publication["guides"])
            if publication
            else 0,
            "published_modules_confirmed": sum(
                r["module"].startswith("modules/")
                and r["publication"] == "confirmed-topic-id"
                for r in coverage
            ),
            "published_modules_missing": sum(
                r["module"].startswith("modules/")
                and r["publication"] == "confirmed-topic-id"
                and r["status"] == "missing"
                for r in coverage
            ),
            "status": "fail"
            if errors or counts["missing"]
            else "needs-review"
            if review
            else "pass",
        }
        if cross_report:
            summary.update(cross_report["summary"])
        report = {
            "schema_version": 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "target": git_info(target),
            "release_source": git_info(source),
            "entry": args.entry,
            "topic_map": args.topic_map,
            "topic_map_sha256": sha((source / args.topic_map).read_text()),
            "attributes": attrs,
            "jtbd_reference_commit": RULE_COMMIT,
            "summary": summary,
            "coverage": coverage,
            "findings": findings,
            "jobs": jobs,
            "categories": categories,
            "additional_map_content": extras,
            "unreachable_jobs": unreachable,
            "duplicate_job_includes": duplicate_job_includes,
            "duplicate_module_inclusions": duplicate_module_inclusions,
            "assembly_review": assembly_reviews,
            "published_sections": published_rows,
            "include_graph": {
                name: [
                    dict(
                        source=n.source,
                        line=n.line,
                        target=n.path,
                        options=n.options,
                        offset=n.offset,
                    )
                    for n in graph.occurrences
                    if n.source
                ]
                for name, graph in (("release", baseline), ("maps", maps))
            },
            "input_hashes": {
                "release": {p: d["sha256"] for p, d in sorted(baseline.files.items())},
                "maps": {p: d["sha256"] for p, d in sorted(maps.files.items())},
            },
        }
        if cross_report:
            report["cross_distro"] = cross_report
        args.output.mkdir(parents=True, exist_ok=True)
        report_dir = args.output / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        (report_dir / "audit.json").write_text(json.dumps(report, indent=2) + "\n")
        if publication:
            (report_dir / "published-index.json").write_text(
                json.dumps(publication, indent=2) + "\n"
            )
        for name, rows, fields in [
            (
                "coverage",
                coverage,
                [
                    "module",
                    "status",
                    "assemblies",
                    "map_jobs",
                    "publication",
                    "published_urls",
                    "replacement_candidates",
                    "remediation",
                    "release_sha256",
                    "map_sha256",
                ],
            ),
            (
                "findings",
                findings,
                [
                    "scope",
                    "severity",
                    "code",
                    "file",
                    "line",
                    "message",
                    "remediation",
                    "rule_source",
                ],
            ),
            (
                "jobs-review",
                jobs,
                [
                    "category",
                    "job",
                    "title",
                    "parent",
                    "procedures",
                    "module_count",
                    "review_status",
                    "editorial_review",
                ],
            ),
            (
                "assembly-review",
                assembly_reviews,
                ["assembly", "title", "guide", "review_status", "remediation"],
            ),
            ("additional-map-content", extras, ["module", "map_jobs", "status"]),
            ("unreachable-jobs", unreachable, ["file", "status"]),
            (
                "duplicate-job-includes",
                duplicate_job_includes,
                ["job", "occurrences", "include_sites", "status"],
            ),
            (
                "duplicate-module-inclusions",
                duplicate_module_inclusions,
                ["module", "job_count", "jobs", "status"],
            ),
            ("published-sections", published_rows, ["id", "url", "modules", "status"]),
        ]:
            write_csv(report_dir / (name + ".csv"), rows, fields)
        if cross_report:
            for name, rows, fields in [
                (
                    "cross-distro-jobs",
                    cross_report["jobs"],
                    [
                        "job",
                        "primary_id",
                        "titles",
                        "sha256",
                        "distros",
                        "distro_count",
                        "categories",
                        "contexts",
                        "entries",
                        "include_sites",
                        "usage_count",
                        "modules",
                        "module_count",
                    ],
                ),
                (
                    "cross-distro-modules",
                    cross_report["modules"],
                    [
                        "module",
                        "primary_id",
                        "titles",
                        "sha256",
                        "distros",
                        "distro_count",
                        "categories",
                        "contexts",
                        "entries",
                        "include_sites",
                        "usage_count",
                        "jobs",
                        "job_count",
                    ],
                ),
                (
                    "cross-distro-overlap",
                    cross_report["overlap"],
                    [
                        "entity_type",
                        "path",
                        "distro_count",
                        "distros",
                        "contexts",
                        "related_jobs",
                    ],
                ),
                (
                    "cross-distro-identity-conflicts",
                    cross_report["identity_conflicts"],
                    [
                        "entity_type",
                        "conflict",
                        "identity",
                        "paths",
                        "distros",
                        "severity",
                        "remediation",
                    ],
                ),
            ]:
                write_csv(report_dir / (name + ".csv"), rows, fields)
        lines = [
            "# Map migration audit",
            "",
            f"Result: **{summary['status']}**",
            "",
            f"Migration target: `{args.entry}` at `{report['target']['commit']}`.",
            f"Release evidence: `{source}` at `{report['release_source']['commit']}`.",
            "",
            "| Check | Count |",
            "| --- | ---: |",
        ]
        lines += [
            f"| {key.replace('_', ' ')} | {value} |"
            for key, value in summary.items()
            if key != "status"
        ]
        lines += ["", "## Missing content", ""]
        lines += [
            f"- `{r['module']}` — source assemblies: {', '.join(r['assemblies'])}. {r['remediation']}"
            for r in coverage
            if r["status"] == "missing"
        ] or ["None detected."]
        if cross_report:
            lines += [
                "",
                "## Cross-distro inventory",
                "",
                f"Entries scanned: {cross_report['summary']['cross_distro_entries']}.",
                f"Canonical jobs: {cross_report['summary']['cross_distro_jobs']}.",
                f"Canonical modules: {cross_report['summary']['cross_distro_modules']}.",
                f"Jobs shared across distros: {cross_report['summary']['cross_distro_shared_jobs']}.",
                f"Modules shared across distros: {cross_report['summary']['cross_distro_shared_modules']}.",
                f"Identity conflicts for review: {cross_report['summary']['cross_distro_identity_conflicts']}.",
                "",
                "Use `cross-distro-jobs.csv` and `cross-distro-modules.csv` to trace category/distro usage. Review exact identity conflicts in `cross-distro-identity-conflicts.csv`; the audit does not merge or generate jobs.",
            ]
        lines += [
            "",
            "## How to use the report",
            "",
            "1. Fix missing includes and unsupported preprocessing in `findings.csv`; these make the inventory incomplete.",
            "2. Restore missing published modules through reachable job includes. Check replacement candidates before deciding whether content was renamed or split.",
            "3. Review `covered-changed` rows in `coverage.csv` against the release source; a newer file can omit older sections.",
            "4. Reconcile `published-sections.csv` and publication findings. Unmatched sections are review items, not automatically missing modules.",
            "5. Fix duplicate job includes in `duplicate-job-includes.csv`; review shared modules in `duplicate-module-inclusions.csv`.",
            "6. Fix structural JTBD findings and complete `jobs-review.csv` and `assembly-review.csv` editorial checks.",
            "7. Rerun the audit, then run the preview and the AsciiDocDITA conversion checks separately.",
            "",
            "Additional map content is informational: the target can include 1.5 work in progress. Unreachable job files do not count as covered.",
            "",
            "This audit checks source reachability and topic-ID evidence. It does not certify rendered content equivalence, editorial quality, or successful DITA conversion.",
        ]
        (report_dir / "README.md").write_text("\n".join(lines) + "\n")
        print(json.dumps(summary, indent=2))
        print(f"Report: {report_dir.resolve() / 'README.md'}")
        return (
            1 if errors or counts["missing"] or (args.strict_review and review) else 0
        )
    except (OSError, ValueError, yaml.YAMLError) as error:
        print(f"Audit configuration/read error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
