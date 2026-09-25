import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from audit_map_migration import (
    Graph,
    cross_distro_entries,
    cross_distro_inventory,
    duplicate_job_include_rows,
    duplicate_module_inclusion_rows,
    job_paths,
    jtbd_audit,
    main,
    topic_entries,
)
from published_map_index import PageIndex, reconcile, source_id_patterns


class AuditTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def put(self, path, text):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        return target

    def graph(self):
        return Graph(self.root, "test", {"rhcl": "", "nbsp": " "})

    def test_topic_map_multi_document_nested_and_distro(self):
        path = self.put(
            "topicmaps.yaml",
            """---
Name: First
Dir: first
Distros: rhcl,other
Topics:
- File: a
- Dir: nested
  Topics:
  - File: b.adoc
  - File: skip
    Distros: other
---
Name: Skip
Dir: hidden
Distros: other
Topics:
- File: absent
""",
        )
        self.assertEqual(
            [x["assembly"] for x in topic_entries(path, "rhcl")],
            ["first/a.adoc", "first/nested/b.adoc"],
        )
        with self.assertRaises(ValueError):
            topic_entries(path, "unknown")

    def test_reachable_only_symlinks_shared_includes_and_conditionals(self):
        self.put(
            "maps/navigation.adoc",
            """:target: a
////
include::modules/missing-comment.adoc[]
////
ifdef::rhcl[]
include::modules/{target}.adoc[]
endif::[]
ifndef::rhcl[]
include::modules/missing-other.adoc[]
endif::[]
include::child.adoc[]
""",
        )
        self.put("maps/child.adoc", "include::modules/a.adoc[]")
        self.put("modules/a.adoc", "= Module\ninclude::nested.adoc[]")
        self.put("modules/nested.adoc", "= Nested")
        self.put("maps/unreachable.adoc", "include::modules/unreachable.adoc[]")
        self.put("modules/unreachable.adoc", "= Not covered")
        (self.root / "maps/modules").symlink_to("../modules", target_is_directory=True)
        graph = self.graph()
        graph.walk("maps/navigation.adoc")
        self.assertEqual(graph.modules(), {"modules/a.adoc", "modules/nested.adoc"})
        self.assertEqual(graph.issues, [])

    def test_cycles_missing_unknown_and_partial_are_not_silent(self):
        self.put(
            "maps/a.adoc",
            """include::b.adoc[]
include::absent.adoc[]
include::{undefined}/module.adoc[]
include::modules/slice.adoc[lines=1..3]
ifeval::[1 == 1]
include::other.adoc[]
endif::[]
""",
        )
        self.put("maps/b.adoc", "include::a.adoc[]")
        self.put("modules/slice.adoc", "= Sliced")
        graph = self.graph()
        graph.walk("maps/a.adoc")
        self.assertEqual(
            {x["code"] for x in graph.issues},
            {
                "include-cycle",
                "missing-include",
                "unresolved-include",
                "partial-include",
                "unsupported-condition",
            },
        )
        self.assertNotIn("modules/slice.adoc", graph.modules())
        self.assertTrue(all(x["line"] > 0 for x in graph.issues))

    def test_jtbd_missing_parent_and_depth(self):
        self.put(
            "maps/navigation.adoc",
            ":_mod-docs-content-type: MAP\n= Product\ninclude::discover.adoc[leveloffset=+1]",
        )
        self.put(
            "maps/discover.adoc",
            ":_mod-docs-content-type: MAP\n= Discover\ninclude::job.adoc[leveloffset=+1]",
        )
        self.put(
            "maps/job.adoc",
            ":_mod-docs-content-type: MAP\ninclude::modules/proc.adoc[leveloffset=+3]",
        )
        self.put(
            "modules/proc.adoc",
            ":_mod-docs-content-type: PROCEDURE\n= Configuring access",
        )
        graph = self.graph()
        root = graph.walk("maps/navigation.adoc")
        findings, jobs, cats = jtbd_audit(graph, root)
        self.assertTrue(
            {"parent-concept", "navigation-depth", "gerund-title"}
            <= {x["code"] for x in findings}
        )
        self.assertEqual(jobs[0]["review_status"], "required")
        self.assertEqual(cats[0]["category"], "Discover")

    def test_unresolved_include_options_block_coverage(self):
        self.put(
            "maps/navigation.adoc",
            "include::modules/a.adoc[tags={selected}]\ninclude::modules/b.adoc[leveloffset=banana]",
        )
        self.put("modules/a.adoc", "= A")
        self.put("modules/b.adoc", "= B")
        graph = self.graph()
        graph.walk("maps/navigation.adoc")
        self.assertNotIn("modules/a.adoc", graph.modules())
        self.assertEqual(
            {x["code"] for x in graph.issues},
            {"unresolved-include-options", "unsupported-leveloffset"},
        )

    def test_valid_parent_is_still_an_editorial_review(self):
        self.put(
            "maps/navigation.adoc",
            ":_mod-docs-content-type: MAP\n= Product\ninclude::discover.adoc[leveloffset=+1]",
        )
        self.put(
            "maps/discover.adoc",
            ":_mod-docs-content-type: MAP\n= Discover\ninclude::job.adoc[leveloffset=+1]",
        )
        self.put(
            "maps/job.adoc",
            ":_mod-docs-content-type: MAP\ninclude::modules/parent.adoc[leveloffset=+0]\ninclude::modules/proc.adoc[leveloffset=+1]",
        )
        self.put(
            "modules/parent.adoc",
            ":_mod-docs-content-type: CONCEPT\n= Control access\nYou can control access to protect information.",
        )
        self.put(
            "modules/proc.adoc",
            ":_mod-docs-content-type: PROCEDURE\n= Configure access",
        )
        graph = self.graph()
        findings, jobs, _ = jtbd_audit(graph, graph.walk("maps/navigation.adoc"))
        self.assertEqual(findings, [])
        self.assertEqual(jobs[0]["parent"], "modules/parent.adoc")

    def test_duplicate_job_file_inclusion_is_reported(self):
        self.put(
            "maps/navigation.adoc",
            ":_mod-docs-content-type: MAP\n= Product\ninclude::discover.adoc[]",
        )
        self.put(
            "maps/discover.adoc",
            ":_mod-docs-content-type: MAP\n= Discover\n"
            "include::jobs/repeated.adoc[]\n"
            "include::jobs/repeated.adoc[]",
        )
        self.put("maps/jobs/repeated.adoc", ":_mod-docs-content-type: MAP\n= Repeat")
        graph = self.graph()
        graph.walk("maps/navigation.adoc")
        rows = duplicate_job_include_rows(graph)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["job"], "maps/jobs/repeated.adoc")
        self.assertEqual(rows[0]["occurrences"], 2)

    def test_duplicate_module_inclusion_across_jobs_is_reported(self):
        self.put(
            "maps/navigation.adoc",
            ":_mod-docs-content-type: MAP\n= Product\ninclude::discover.adoc[]",
        )
        self.put(
            "maps/discover.adoc",
            ":_mod-docs-content-type: MAP\n= Discover\n"
            "include::jobs/first.adoc[]\n"
            "include::jobs/second.adoc[]",
        )
        for job in ("first", "second"):
            self.put(
                f"maps/jobs/{job}.adoc",
                ":_mod-docs-content-type: MAP\n"
                f"= {job.title()}\ninclude::../../modules/shared.adoc[]",
            )
        self.put("modules/shared.adoc", ":_mod-docs-content-type: CONCEPT\n= Shared")
        graph = self.graph()
        navigation = graph.walk("maps/navigation.adoc")
        rows = duplicate_module_inclusion_rows(job_paths(navigation, graph))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["module"], "modules/shared.adoc")
        self.assertEqual(rows[0]["job_count"], 2)
        self.assertEqual(
            rows[0]["jobs"], ["maps/jobs/first.adoc", "maps/jobs/second.adoc"]
        )

    def test_cross_distro_inventory_tracks_shared_jobs_and_modules(self):
        for distro, category in (("rosa", "Install"), ("virt", "Configure")):
            category_file = category.casefold() + ".adoc"
            self.put(
                f"maps/{distro}/navigation.adoc",
                ":_mod-docs-content-type: MAP\n"
                f"= {distro.upper()}\ninclude::{category_file}[]",
            )
            self.put(
                f"maps/{distro}/{category_file}",
                ":_mod-docs-content-type: MAP\n"
                f"= {category}\ninclude::../jobs/shared.adoc[]",
            )
        self.put(
            "maps/jobs/shared.adoc",
            ":_mod-docs-content-type: MAP\n"
            '[id="shared-job"]\n'
            "= Manage a shared service\n"
            "include::../../modules/shared.adoc[]",
        )
        self.put(
            "modules/shared.adoc",
            ":_mod-docs-content-type: CONCEPT\n"
            '[id="shared-module"]\n'
            "= Shared service",
        )
        entries = cross_distro_entries(self.root)
        report, findings = cross_distro_inventory(
            self.root, entries, {"nbsp": " "}
        )
        self.assertEqual(findings, [])
        self.assertEqual(report["summary"]["cross_distro_shared_jobs"], 1)
        self.assertEqual(report["summary"]["cross_distro_shared_modules"], 1)
        self.assertEqual(report["jobs"][0]["distros"], ["rosa", "virt"])
        self.assertEqual(
            report["jobs"][0]["contexts"], ["rosa:Install", "virt:Configure"]
        )
        self.assertEqual(report["modules"][0]["job_count"], 1)
        self.assertEqual(report["identity_conflicts"], [])

    def test_cross_distro_inventory_blocks_same_id_with_different_content(self):
        for distro, job in (("rosa", "first"), ("virt", "second")):
            self.put(
                f"maps/{distro}/navigation.adoc",
                ":_mod-docs-content-type: MAP\n"
                f"= {distro.upper()}\ninclude::category.adoc[]",
            )
            self.put(
                f"maps/{distro}/category.adoc",
                ":_mod-docs-content-type: MAP\n"
                f"= Configure\ninclude::../jobs/{job}.adoc[]",
            )
            self.put(
                f"maps/jobs/{job}.adoc",
                ":_mod-docs-content-type: MAP\n"
                '[id="conflicting-job"]\n'
                f"= {job.title()} outcome\n{distro} content",
            )
        report, findings = cross_distro_inventory(
            self.root, cross_distro_entries(self.root), {"nbsp": " "}
        )
        conflicts = report["identity_conflicts"]
        self.assertTrue(
            any(row["conflict"] == "same-id-different-content" for row in conflicts)
        )
        self.assertTrue(
            any(
                row["code"] == "cross-distro-same-id-different-content"
                and row["severity"] == "error"
                for row in findings
            )
        )

    def test_publication_match_includes_missing_inventory_and_unmatched_sections(self):
        self.put("modules/published.adoc", '[id="published_{context}"]\n= Published')
        self.put("modules/absent.adoc", '[id="absent_{context}"]\n= Absent')
        baseline = self.graph()
        baseline.attributes["context"] = "old"
        baseline.walk("modules/published.adoc")
        maps = self.graph()
        maps.walk("modules/published.adoc")
        sources = {"modules/published.adoc": {"book.adoc"}}
        snapshot = {
            "schema_version": 1,
            "guides": [
                {
                    "url": "https://docs.redhat.com/test",
                    "ids": ["published_old", "absent_old", "inline-section"],
                }
            ],
        }
        rows, issues = reconcile(snapshot, baseline, maps, sources)
        self.assertIn("modules/absent.adoc", sources)
        self.assertTrue(
            any(x["code"] == "published-module-outside-topic-map" for x in issues)
        )
        self.assertTrue(any(x["status"] == "unmatched-section-review" for x in rows))
        self.assertNotIn("modules/absent.adoc", maps.modules())

    def test_publication_parser_ignores_ui_ids_and_matches_context_only(self):
        parser = PageIndex()
        parser.feed(
            '<div class></div><a id="toc-x" href="/guide">Guide</a><section class="section" id="topic_old"><h2>Title</h2></section>'
        )
        self.assertEqual(parser.sections, {"topic_old"})
        regex = source_id_patterns('[id="topic_{context}"]', {"context": "old"})[0]
        self.assertTrue(regex.fullmatch("topic_old"))
        self.assertFalse(regex.fullmatch("different_old"))
        self.assertFalse(regex.fullmatch("topic_14-additional-resources"))

    def test_copied_assembly_id_does_not_prove_unused_module_was_published(self):
        self.put("book/start.adoc", '[id="assembly-id"]\n= Assembly')
        self.put("modules/new-landing.adoc", '[id="assembly-id"]\n= New landing')
        baseline = self.graph()
        baseline.walk("book/start.adoc")
        sources = {}
        snapshot = {
            "schema_version": 1,
            "guides": [{"url": "https://docs.redhat.com/test", "ids": ["assembly-id"]}],
        }
        rows, _ = reconcile(snapshot, baseline, self.graph(), sources)
        self.assertEqual(sources, {})
        self.assertEqual(rows[0]["status"], "assembly-or-snippet-section")

    def test_failed_publication_fetch_is_blocking_and_cannot_pass_as_empty(self):
        rows, issues = reconcile(
            {
                "schema_version": 1,
                "guides": [],
                "errors": [{"url": "https://docs.redhat.com/test", "error": "403"}],
            },
            self.graph(),
            self.graph(),
            {},
        )
        self.assertEqual(rows, [])
        self.assertEqual(
            {x["code"] for x in issues}, {"publication-fetch", "publication-empty"}
        )
        self.assertTrue(all(x["severity"] == "error" for x in issues))

    def test_published_module_outside_inventory_brings_nested_dependencies(self):
        self.put("modules/new.adoc", '[id="new"]\n= New\ninclude::child.adoc[]')
        self.put("modules/child.adoc", "= Child")
        sources = {}
        snapshot = {
            "schema_version": 1,
            "guides": [{"url": "https://docs.redhat.com/test", "ids": ["new"]}],
        }
        reconcile(snapshot, self.graph(), self.graph(), sources)
        self.assertIn("modules/child.adoc", sources)

    def test_cli_compares_separate_release_and_map_tree_and_does_not_count_orphan(self):
        self.put(
            "release/_topic_maps/_topic_map.yml",
            "Dir: book\nDistros: rhcl\nTopics:\n- File: start\n",
        )
        self.put(
            "release/book/start.adoc",
            "include::modules/shared.adoc[]\ninclude::modules/lost.adoc[]",
        )
        self.put("release/modules/shared.adoc", "= Original")
        self.put("release/modules/lost.adoc", "= Lost")
        self.put(
            "target/maps/rhcl/navigation.adoc",
            ":_mod-docs-content-type: MAP\n= Product\ninclude::discover.adoc[leveloffset=+1]",
        )
        self.put(
            "target/maps/rhcl/discover.adoc",
            ":_mod-docs-content-type: MAP\n= Discover\ninclude::modules/shared.adoc[leveloffset=+1]",
        )
        self.put("target/modules/shared.adoc", "= Changed for 1.5")
        self.put("target/modules/lost.adoc", "= Lost")
        self.put("target/maps/jobs/orphan.adoc", "include::modules/lost.adoc[]")
        args = [
            "--repo-root",
            str(self.root / "target"),
            "--source-root",
            str(self.root / "release"),
            "--output",
            str(self.root / "report"),
        ]
        with contextlib.redirect_stdout(io.StringIO()):
            result = main(args)
        report = json.loads((self.root / "report/reports/audit.json").read_text())
        self.assertEqual(result, 1)
        self.assertEqual(report["summary"]["missing"], 1)
        self.assertEqual(report["summary"]["covered_changed"], 1)
        self.assertEqual(report["summary"]["unreachable_jobs"], 1)
        self.assertTrue((self.root / "report/reports/coverage.csv").is_file())
        self.assertTrue(
            (self.root / "report/reports/duplicate-job-includes.csv").is_file()
        )
        self.assertTrue(
            (self.root / "report/reports/duplicate-module-inclusions.csv").is_file()
        )
        self.assertTrue((self.root / "report/reports/README.md").is_file())
        self.assertNotIn("cross_distro", report)
        self.assertFalse(
            (self.root / "report/reports/cross-distro-jobs.csv").exists()
        )

        cross_args = args[:-1] + [
            str(self.root / "cross-report"),
            "--cross-distro-audit",
        ]
        with contextlib.redirect_stdout(io.StringIO()):
            cross_result = main(cross_args)
        cross_report = json.loads(
            (self.root / "cross-report/reports/audit.json").read_text()
        )
        self.assertEqual(cross_result, 1)
        self.assertEqual(cross_report["summary"]["cross_distro_entries"], 1)
        self.assertIn("cross_distro", cross_report)
        self.assertTrue(
            (self.root / "cross-report/reports/cross-distro-jobs.csv").is_file()
        )
        self.assertTrue(
            (self.root / "cross-report/reports/cross-distro-modules.csv").is_file()
        )


if __name__ == "__main__":
    unittest.main()
