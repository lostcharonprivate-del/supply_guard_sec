"""Manifest parsing, against real lockfiles committed as fixtures.

The npm fixture is a genuine `npm install --package-lock-only` output with 244
entries, not a hand-written sample, because the interesting behaviour (hoisting,
dedup, dev propagation) only appears at that scale.
"""

from __future__ import annotations

import pytest

from supplyguard.ecosystems import ManifestParseError, adapter_for_manifest, get_adapter
from tests.conftest import load_fixture


class TestRouting:
    @pytest.mark.parametrize(
        ("filename", "expected"),
        [
            ("package-lock.json", "npm"),
            ("yarn.lock", "npm"),
            ("requirements.txt", "pypi"),
            ("requirements-dev.txt", "pypi"),
            ("poetry.lock", "pypi"),
            ("uv.lock", "pypi"),
            ("Gemfile.lock", "rubygems"),
            ("pom.xml", "maven"),
            ("app/gradle.lockfile", "maven"),
        ],
    )
    def test_manifest_routes_to_the_right_adapter(self, filename: str, expected: str) -> None:
        adapter = adapter_for_manifest(filename)
        assert adapter is not None and adapter.name == expected

    def test_unsupported_manifest_routes_nowhere(self) -> None:
        assert adapter_for_manifest("go.mod") is None
        assert adapter_for_manifest("Cargo.lock") is None

    def test_lockfile_wins_over_loose_manifest(self) -> None:
        # Both adapters claim package.json; the resolved lockfile must be preferred
        # when a directory contains both.
        assert adapter_for_manifest("package-lock.json").is_lockfile("package-lock.json")
        assert not adapter_for_manifest("package.json").is_lockfile("package.json")


class TestNpm:
    @pytest.fixture(scope="class")
    def graph(self):
        return get_adapter("npm").parse_manifest(
            load_fixture("npm", "package-lock.json"), "package-lock.json"
        )

    def test_parses_the_full_transitive_tree(self, graph) -> None:
        assert len(graph) > 200

    def test_direct_dependencies_match_the_manifest(self, graph) -> None:
        assert graph.direct_names == {"express", "lodash", "minimist", "mocha"}

    def test_depth_reflects_dependency_distance_not_hoisting(self, graph) -> None:
        """npm hoists packages to the top of node_modules regardless of depth.

        `accepts` is installed at `node_modules/accepts` but is only reachable
        through express, so its depth must be 1 rather than 0.
        """
        accepts = graph.nodes["accepts@1.3.8"]
        assert accepts.depth == 1
        assert not accepts.is_direct
        assert "express@4.17.1" in accepts.parents

    def test_a_package_reachable_directly_and_transitively_counts_as_direct(self, graph) -> None:
        # lodash is a declared dependency and also pulled in by mocha's tree.
        lodash = graph.nodes["lodash@4.17.15"]
        assert lodash.is_direct and lodash.depth == 0

    def test_dev_dependencies_are_marked(self, graph) -> None:
        assert graph.nodes["mocha@8.0.0"].is_dev
        assert not graph.nodes["express@4.17.1"].is_dev

    def test_edges_are_recorded(self, graph) -> None:
        assert ("express@4.17.1", "accepts@1.3.8") in graph.edges

    def test_package_json_is_flagged_as_unresolved(self) -> None:
        graph = get_adapter("npm").parse_manifest(
            load_fixture("npm", "package.json"), "package.json"
        )
        assert all(p.raw.get("unresolved") for p in graph.packages)
        assert any("package-lock.json" in w for w in graph.warnings)

    def test_lockfile_v1_nesting(self) -> None:
        content = """{
          "lockfileVersion": 1,
          "dependencies": {
            "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}},
            "c": {"version": "3.0.0", "dev": true}
          }
        }"""
        graph = get_adapter("npm").parse_manifest(content, "package-lock.json")
        assert graph.nodes["a@1.0.0"].depth == 0
        assert graph.nodes["b@2.0.0"].depth == 1
        assert graph.nodes["c@3.0.0"].is_dev

    def test_scoped_names_survive_parsing(self) -> None:
        content = """{
          "lockfileVersion": 3,
          "packages": {
            "": {"dependencies": {"@scope/pkg": "^1.0.0"}},
            "node_modules/@scope/pkg": {"version": "1.2.3"}
          }
        }"""
        graph = get_adapter("npm").parse_manifest(content, "package-lock.json")
        assert "@scope/pkg@1.2.3" in graph.nodes

    def test_malformed_json_raises_a_useful_error(self) -> None:
        with pytest.raises(ManifestParseError, match="not valid JSON"):
            get_adapter("npm").parse_manifest("{not json", "package-lock.json")


class TestPyPI:
    def test_requirements_parses_only_pinned_lines(self) -> None:
        content = (
            "# a comment\n"
            "requests==2.31.0\n"
            'Django[argon2]==3.2.0 ; python_version>"3.7"\n'
            "flask>=2.0\n"          # unpinned: cannot be resolved
            "-r base.txt\n"          # include: not uploaded
            "urllib3==1.26.5 --hash=sha256:abc\n"
        )
        graph = get_adapter("pypi").parse_manifest(content, "requirements.txt")
        assert {p.name for p in graph.packages} == {"requests", "Django", "urllib3"}
        assert any("not pinned" in w for w in graph.warnings)

    def test_pep503_normalisation(self) -> None:
        adapter = get_adapter("pypi")
        assert adapter.normalize_name("Zope.Interface") == "zope-interface"
        assert adapter.normalize_name("typing_extensions") == "typing-extensions"

    def test_uv_lock_derives_depth_from_edges(self) -> None:
        graph = get_adapter("pypi").parse_manifest(
            load_fixture("pypi", "uv.lock"), "uv.lock"
        )
        assert len(graph) > 5
        # django is depended on by the root project, so it is not itself a root.
        by_name = {p.name: p for p in graph.packages}
        assert "django" in by_name
        assert by_name["django"].depth >= 1
        # asgiref is a dependency of django, so it must sit deeper still.
        assert by_name["asgiref"].depth > by_name["django"].depth

    def test_pipfile_lock(self) -> None:
        content = """{
          "default": {"requests": {"version": "==2.25.1"}},
          "develop": {"pytest": {"version": "==7.0.0"}}
        }"""
        graph = get_adapter("pypi").parse_manifest(content, "Pipfile.lock")
        assert graph.nodes["requests@2.25.1"].is_dev is False
        assert graph.nodes["pytest@7.0.0"].is_dev is True

    def test_malformed_toml_raises(self) -> None:
        with pytest.raises(ManifestParseError, match="not valid TOML"):
            get_adapter("pypi").parse_manifest("[[[bad", "poetry.lock")


class TestRubyGems:
    @pytest.fixture(scope="class")
    def graph(self):
        return get_adapter("rubygems").parse_manifest(
            load_fixture("rubygems", "Gemfile.lock"), "Gemfile.lock"
        )

    def test_declared_gems_are_direct(self, graph) -> None:
        assert graph.direct_names == {"actionpack", "nokogiri", "rake"}

    def test_transitive_gems_get_depth_from_the_specs_block(self, graph) -> None:
        by_name = {p.name: p for p in graph.packages}
        assert by_name["actionpack"].depth == 0
        assert by_name["activesupport"].depth == 1
        assert by_name["concurrent-ruby"].depth == 2

    def test_versions_are_captured(self, graph) -> None:
        assert {p.name: p.version for p in graph.packages}["rack"] == "2.0.7"


class TestMaven:
    @pytest.fixture(scope="class")
    def graph(self):
        return get_adapter("maven").parse_manifest(
            load_fixture("maven", "pom.xml"), "pom.xml"
        )

    def test_coordinates_are_group_and_artifact(self, graph) -> None:
        assert "org.apache.logging.log4j:log4j-core@2.14.1" in graph.nodes

    def test_property_placeholders_are_expanded(self, graph) -> None:
        # jackson's version comes from ${jackson.version}.
        assert "com.fasterxml.jackson.core:jackson-databind@2.9.8" in graph.nodes

    def test_version_falls_back_to_dependency_management(self, graph) -> None:
        # spring-core declares no version; it is managed by the BOM section.
        assert "org.springframework:spring-core@5.2.0.RELEASE" in graph.nodes

    def test_test_scope_is_treated_as_dev(self, graph) -> None:
        assert graph.nodes["junit:junit@4.12"].is_dev

    def test_warns_that_the_tree_is_direct_only(self, graph) -> None:
        assert any("transitive" in w for w in graph.warnings)

    def test_malformed_xml_raises(self) -> None:
        with pytest.raises(ManifestParseError, match="not valid XML"):
            get_adapter("maven").parse_manifest("<project", "pom.xml")
