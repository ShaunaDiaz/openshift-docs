# Audit the RHCL maps before DITA migration

`audit_map_migration.py` audits the content reachable from
`maps/rhcl/navigation.adoc`. Its purpose is to show whether the MAP hierarchy
retains the published RHCL **1.4** content and follows the JTBD structure.
RHCL 1.5 is work in progress. Additional content in the target maps is reported
as information, not as a coverage failure.

The script reads source files without changing them. It does not fetch Git
branches, alter maps, generate missing content, or invoke map-tools. It needs
Python 3.10+, PyYAML, and (for the optional live-site check) curl. Reports are
written under the `reports/` folder inside the output directory you select.

## Reuse with other OpenShift content

The audit can be used with other OpenShift products or distros that use the
same map and include conventions. The main inputs are configurable:

- `--repo-root`: target repository.
- `--source-root`: published-release checkout used as the comparison baseline.
- `--entry`: navigation map, such as `maps/microshift/navigation.adoc`.
- `--distro`: distro name, such as `microshift`.
- `--topic-map`: topic-map YAML path.
- `--attribute`: additional AsciiDoc attributes.
- `--published-url` or `--published-snapshot`: optional published-site reconciliation.

For example:

```bash
python3 scripts/audit_tools/audit_map_migration.py \
  --repo-root /path/to/openshift-docs \
  --source-root /path/to/microshift-release \
  --entry maps/microshift/navigation.adoc \
  --distro microshift \
  --output /tmp/microshift-audit
```

The target repository should use the general OpenShift conventions of
`maps/<distro>/navigation.adoc`, shared `maps/jobs/`, and `modules/`,
`snippets/`, and `assemblies/` content. The topic-map inventory should use the
OpenShift `Dir`, `Topics`, `File`, and optional `Distros` schema. The core
map/source audit is reusable; the optional published-site check might need
adjustment if another product's documentation portal has a substantially
different structure.

## Run from the repository root

Use a separate checkout of `rhcl-docs-1.4` as release evidence. The maps to be
migrated remain in your working checkout. For example:

```bash
python3 -m venv /tmp/rhcl-audit-venv
/tmp/rhcl-audit-venv/bin/python -m pip install PyYAML

release_source=$(mktemp -d /tmp/rhcl-source-1.4.XXXXXX)
git clone --depth 1 --branch rhcl-docs-1.4 \
  https://github.com/ShaunaDiaz/openshift-docs.git "$release_source"

/tmp/rhcl-audit-venv/bin/python scripts/audit_tools/audit_map_migration.py \
  --source-root "$release_source" \
  --published-url https://docs.redhat.com/en/documentation/red_hat_connectivity_link/1.4 \
  --output /tmp/rhcl-map-audit
```

If Python and PyYAML are already installed, use `python3` directly.
From inside `maps/`, use `python3 ../scripts/audit_tools/audit_map_migration.py`
with the same arguments. The target repository defaults to the repository
containing the script; `--repo-root PATH` can select another checkout. `--entry`
selects a different navigation file inside its `maps/` directory.

This repository calls its assembly inventory `_topic_maps/_topic_map.yml`.
If your inventory is named `topicmaps.yaml`, use `--topic-map topicmaps.yaml`.
The filename is configurable; its schema must be the OpenShift `Dir`, `Topics`,
`File`, and optional `Distros` structure. Nested directories, YAML documents,
list entries, and inherited distro filters are supported. `--distro rhcl` is
the default.

`--attribute NAME=VALUE` supplies initial AsciiDoc attributes. The `rhcl`
attribute is defined by default. Attributes declared in the source then take
effect in include order, as part of this conservative source analysis.

## Reproduce the publication check offline

The live check saves an index of guide URLs, section IDs, fetch time, and page
hashes. Reuse it with the same release checkout:

```bash
python3 scripts/audit_tools/audit_map_migration.py \
  --source-root "$release_source" \
  --published-snapshot /tmp/rhcl-map-audit/reports/published-index.json \
  --output /tmp/rhcl-map-audit-repeat
```

Omit both publication options for a source-only comparison. Such a run has
**not checked the published site**. A new live run is needed to pick up later
publication changes. Reports record source and target Git commits, worktree
status, attributes, and hashes of the actual files read, so a dirty checkout
is not mistaken for the recorded commit's exact contents.

## How coverage is determined

The process adapts the idea in the OpenShift AI
`scripts/find-module-references.sh`: walk the publication entry points, walk
the maps, and compare the reachable source files. Here the publication entry
points are the RHCL assemblies selected by the topic-map YAML, rather than
`master.adoc` files.

The target walk starts only at the selected navigation map. Files in the
repository, or even in `maps/jobs/`, do not count as covered unless reachable
through that entry. Includes with `toc="no"` still count as content.

Canonical repository-relative paths identify modules, including paths reached
through symlinks. Each coverage row identifies the release assemblies and
target jobs. Nested module and snippet includes are followed too. The script
also reports inactive files in the repository's shared `maps/jobs/` directory;
some might intentionally belong to another distro.

| Status | Meaning | Action |
| --- | --- | --- |
| `covered-identical` | Same file is reachable and its raw source matches the release checkout | Review the assembly context and rendering separately |
| `covered-changed` | Same file is reachable, but the source differs | Compare it with 1.4; check that published sections were retained |
| `missing` | Release file is not reachable from the selected maps | Include it in an appropriate job or verify/document a replacement |
| `additional-map-content` | Reachable module has no counterpart in the selected release inventory | Informational; can be new 1.5 content or new job framing |

Identical content or IDs in another filename are listed as replacement
**candidates**, never silently accepted as equivalent. This version has no
waiver mechanism: intentional removals or rewrites remain explicit review
work. It does not decide automatically that an old module is obsolete.

The published-site check reads every guide linked from the selected version's
landing page and its single-page HTML. It matches explicit source IDs using
known assembly contexts. A published ID can reveal a module present in the
release source but omitted from its current topic-map inventory; those modules
are added to the comparison and flagged. This matters because a release branch
can be reorganized ahead of publication.

Unmatched or ambiguous IDs stay in a review list. They can represent generated
headings, assembly prose, changed IDs, or genuinely absent content. A copied
assembly ID in an unused module is not sufficient to prove publication. An ID
match proves that a corresponding section exists, not that source text exactly
matches the deployed page. There is no exact deployed Git SHA exposed by this
check.

## JTBD criteria and scope

Rules were read from the requested
[JTBD reference directory](https://gitlab.cee.redhat.com/ccs-ai/ccs-ai-agentic-workflow/-/tree/main/plugins/jtbd-tools/reference),
at commit `6cd4e1a4c78c95fb3496e62f4f5d8d4fd6a7fb76`.
Each finding links to the relevant reference document. There is no runtime
dependency on that repository or map-tools.

| Criterion | Audit treatment | Reference |
| --- | --- | --- |
| Category and navigation nodes are MAPs | Automatic type check | `pitfalls.md` |
| Categories organize jobs, rather than carry explanatory content | Prose detection flags review | `toc-guidelines.md` |
| Main jobs have a parent concept | First content include must be CONCEPT at the job's level; missing parent is an error for operational jobs | `methodology.md` |
| Reference/release-note collections may not be main jobs | Missing concept in these categories requires classification review | `consistency-guidelines.md` |
| Parent concepts have one heading | Automatic heading check | `pitfalls.md` |
| At most three levels below category | Check projected source heading level, using include offsets | `toc-guidelines.md` |
| Discover is present | Automatic check | `consistency-guidelines.md` |
| Job titles are unique | Automatic check across direct category children | `consistency-guidelines.md` |
| A job file is included only once | Automatic reachable-graph check; repeated inclusion is blocking | This audit |
| Modules are not unintentionally shared across jobs | Automatic check; shared modules require review, not an automatic failure | This audit |
| Procedure/job titles use imperatives; concepts/references use noun phrases | Common gerunds flagged; grammatical correctness remains editorial | `consistency-guidelines.md` |
| Avoid redundant prefixes and persona-gated headings | Common patterns flagged | `consistency-guidelines.md` |
| Verification belongs within its execution job | Standalone verification titles flagged for review | `toc-guidelines.md` |
| A real outcome; parent explains what/why/how; themed approaches; prerequisite order; links; no duplicated overview/content | Explicit checklist for every main job | `methodology.md`, `toc-guidelines.md` |

The directory layout remains `maps/rhcl` plus shared `maps/jobs`; this audit does
not require adopting another product's folder convention. It does not impose
the per-book analysis artifact's sequential job numbering or 10–15-job target
on the entire product. Title uniqueness below the main-job level, appropriate
grouping, natural language, and semantic completeness need editorial review.
The audit does not use cosine similarity, Jaccard similarity, or another
semantic-similarity heuristic to identify duplicate jobs. It reports only
deterministic duplicate includes and module reuse across reachable jobs.

This is a source audit, not an AsciiDoc or DITA renderer. `leveloffset` supports
relative and absolute numeric values; projected navigation depths do not model
every converter's chunking behavior. The `:chunk-to-content:` and `:topichead:`
conversion rules are outside this audit's JTBD reference checks. Run the
converter and preview as separate gates.

## Reports and remediation

Open `reports/README.md` in the output directory for the results and next steps.

- `reports/coverage.csv`: required module/snippet, status, source assemblies, target
  jobs, published links, hashes, and remediation.
- `reports/findings.csv`: broken includes, unsupported preprocessing, JTBD rules, and
  publication reconciliation issues, with source locations and fixes.
- `reports/jobs-review.csv`: reachable top jobs, parent concepts, and editorial checks.
- `reports/assembly-review.csv`: check content written directly in assemblies, such as
  introductions, prerequisites, and additional resources.
- `reports/published-sections.csv`: all published section IDs and matching source files.
- `reports/additional-map-content.csv`: extra target modules, including possible 1.5 work.
- `reports/unreachable-jobs.csv`: shared job files outside the selected navigation graph.
- `reports/duplicate-job-includes.csv`: job files included more than once, with include locations.
- `reports/duplicate-module-inclusions.csv`: modules included by more than one reachable job for review.
- `reports/audit.json`: complete report and provenance for automation/preview integration.
- `reports/published-index.json`: reusable publication snapshot when requested.

Fix missing includes first, then missing published content and structural
findings. Review changed sources and assembly-only prose before deciding that
the migration preserves the content. Rerun the audit after edits. Build the
preview and run AsciiDocDITA validation after those issues are resolved.

Exit codes: **0** means no detected blocking coverage/structural errors;
**1** means missing required files or blocking findings; **2** means a
configuration/read error. `--strict-review` also returns 1 for outstanding
review work. A report can say `needs-review` with exit 0; it never claims that
editorial approval or DITA conversion succeeded.

## Conservative preprocessing limits

The walker handles comments, attribute substitution, `ifdef`/`ifndef`, nested
includes, cycle detection, and this repository's relative/symlink/root-based
include conventions. Missing files, unresolved include attributes, remote or
external includes, malformed directives, `ifeval`, and `tag`/`lines` selections
are blocking findings. A partial include is not counted as whole-file coverage.
It does not execute Asciidoctor extensions or custom include processors.

Module identity and byte equality do not prove that all prose, images, xrefs,
conditional variants, or the rendered DITA output are preserved. The separate
editorial checks and conversion tests are necessary for that conclusion.

## Tests

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/audit_tools/tests -v
```
