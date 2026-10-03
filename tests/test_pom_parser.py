"""Tests for vibeguard.layer1_static.pom_parser."""

from __future__ import annotations

import time
from pathlib import Path

from vibeguard.layer1_static._parsing_guards import ParseStatus
from vibeguard.layer1_static.pom_parser import parse_pom_file, resolve_inherited_versions

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_parse_extracts_dependencies_with_resolved_property_version() -> None:
    result = parse_pom_file(FIXTURES_DIR / "vulnerable-pom.xml")

    assert result.status == ParseStatus.OK
    deps_by_artifact = {d.artifact_id: d for d in result.dependencies}

    log4j = deps_by_artifact["log4j-core"]
    assert log4j.group_id == "org.apache.logging.log4j"
    assert log4j.version == "2.14.1"
    assert log4j.raw_version == "${log4j.version}"
    assert log4j.line == 16


def test_parse_direct_version_is_used_as_is() -> None:
    result = parse_pom_file(FIXTURES_DIR / "vulnerable-pom.xml")
    deps_by_artifact = {d.artifact_id: d for d in result.dependencies}

    jackson = deps_by_artifact["jackson-databind"]
    assert jackson.version == "2.15.0"
    assert jackson.raw_version == "2.15.0"


def test_parse_unresolvable_property_yields_none_version_not_a_guess() -> None:
    """A property not found locally (e.g. from an inaccessible parent POM)

    must resolve to None, never a guessed or default value.
    """
    result = parse_pom_file(FIXTURES_DIR / "vulnerable-pom.xml")
    deps_by_artifact = {d.artifact_id: d for d in result.dependencies}

    snakeyaml = deps_by_artifact["snakeyaml"]
    assert snakeyaml.version is None
    assert snakeyaml.raw_version == "${snakeyaml.version}"


def test_parse_handles_pom_without_namespace_declaration(tmp_path: Path) -> None:
    """Not every real-world pom.xml declares the Maven namespace explicitly."""
    pom_file = tmp_path / "pom.xml"
    pom_file.write_text(
        "<project>\n"
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>junit</groupId>\n"
        "      <artifactId>junit</artifactId>\n"
        "      <version>4.13.2</version>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n"
    )

    result = parse_pom_file(pom_file)

    assert result.status == ParseStatus.OK
    assert len(result.dependencies) == 1
    assert result.dependencies[0].artifact_id == "junit"


def test_parse_malformed_xml_reports_failure_not_exception(tmp_path: Path) -> None:
    pom_file = tmp_path / "pom.xml"
    pom_file.write_text("<project><dependencies><dependency>\n")

    result = parse_pom_file(pom_file)

    assert result.status == ParseStatus.PARSE_FAILED
    assert result.error_message
    assert result.dependencies == ()


def test_parse_empty_file(tmp_path: Path) -> None:
    pom_file = tmp_path / "pom.xml"
    pom_file.write_text("")

    result = parse_pom_file(pom_file)

    assert result.status == ParseStatus.EMPTY_FILE


def test_parse_missing_file_does_not_raise(tmp_path: Path) -> None:
    result = parse_pom_file(tmp_path / "does-not-exist" / "pom.xml")

    assert result.status == ParseStatus.PARSE_FAILED
    assert result.error_message


def test_parse_file_too_large_is_rejected(tmp_path: Path) -> None:
    pom_file = tmp_path / "pom.xml"
    pom_file.write_text("<project></project>\n" * 100)

    result = parse_pom_file(pom_file, max_bytes=10)

    assert result.status == ParseStatus.FILE_TOO_LARGE


def test_parse_ignores_dependency_management_entries(tmp_path: Path) -> None:
    """Only direct <dependencies>, not <dependencyManagement>, are extracted."""
    pom_file = tmp_path / "pom.xml"
    pom_file.write_text(
        "<project>\n"
        "  <dependencyManagement>\n"
        "    <dependencies>\n"
        "      <dependency>\n"
        "        <groupId>com.example</groupId>\n"
        "        <artifactId>managed-only</artifactId>\n"
        "        <version>1.0.0</version>\n"
        "      </dependency>\n"
        "    </dependencies>\n"
        "  </dependencyManagement>\n"
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>com.example</groupId>\n"
        "      <artifactId>actually-used</artifactId>\n"
        "      <version>1.0.0</version>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n"
    )

    result = parse_pom_file(pom_file)

    artifact_ids = {d.artifact_id for d in result.dependencies}
    assert artifact_ids == {"actually-used"}


def test_parse_rejects_entity_expansion_bomb_instead_of_hanging(tmp_path: Path) -> None:
    """A 'billion laughs'-style entity expansion payload must fail closed.

    Verified empirically that CPython's bundled expat parser already
    rejects this with a ParseError rather than hanging or consuming
    excessive memory (a native protection since Python 3.7.1) - this
    test locks that behavior in as a permanent regression check.
    """
    entities = '<!ENTITY lol0 "lol">\n'
    for i in range(1, 10):
        refs = ("&lol" + str(i - 1) + ";") * 10
        entities += f'<!ENTITY lol{i} "{refs}">\n'
    payload = f"<?xml version='1.0'?>\n<!DOCTYPE lolz [\n{entities}]>\n<lolz>&lol9;</lolz>"
    pom_file = tmp_path / "pom.xml"
    pom_file.write_text(payload)

    start = time.monotonic()
    result = parse_pom_file(pom_file)
    elapsed = time.monotonic() - start

    assert result.status == ParseStatus.PARSE_FAILED
    assert elapsed < 5.0


def test_parse_rejects_small_entity_expansion_not_just_large_bombs(tmp_path: Path) -> None:
    """A small internal entity previously parsed successfully - a real gap.

    CPython's expat amplification-ceiling protection only trips once a
    payload is large enough; a small ``<!ENTITY>`` well under that
    threshold parsed *successfully* and had its expansion silently
    substituted into the tree, confirmed directly by testing (not
    assumed) before this fix. Only the "billion laughs"-scale bomb was
    covered by the earlier regression test, leaving small/moderate
    entity injection un-guarded. The blanket <!DOCTYPE> rejection below
    closes that gap regardless of payload size.
    """
    pom_file = tmp_path / "pom.xml"
    pom_file.write_text(
        '<?xml version="1.0"?>\n'
        "<!DOCTYPE project [\n"
        '  <!ENTITY lol "lol">\n'
        "]>\n"
        "<project>\n"
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>com.example</groupId>\n"
        "      <artifactId>lib</artifactId>\n"
        "      <version>&lol;</version>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n"
    )

    result = parse_pom_file(pom_file)

    assert result.status == ParseStatus.PARSE_FAILED


def test_parse_does_not_resolve_external_entities(tmp_path: Path) -> None:
    """XXE (reading local files via an external entity) must not succeed."""
    pom_file = tmp_path / "pom.xml"
    pom_file.write_text(
        '<?xml version="1.0"?>\n'
        "<!DOCTYPE root [\n"
        '  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n'
        "]>\n"
        "<root>&xxe;</root>\n"
    )

    result = parse_pom_file(pom_file)

    assert result.status == ParseStatus.PARSE_FAILED


# -- Multi-module (reactor) parent/dependencyManagement resolution ----------
#
# A real, common gap: most of a project's dependencies typically have no
# <version> at all, inherited from a parent's <dependencyManagement> -
# see IMPLEMENTATION_LOG.md's 2026-09-02 entry, which measured this
# directly (19/24 unresolved on spring-petclinic-rest, 162/204 on
# quarkus-super-heroes). resolve_inherited_versions closes this only when
# the parent is a sibling pom.xml in the same scan (a true multi-module
# "reactor" project) - not when the parent is a third-party BOM resolved
# from Maven Central/~/.m2, which is what both of those real repos
# actually do (stated explicitly in the module's own docstring).


def _write_parent_pom(path: Path) -> None:
    path.write_text(
        "<project>\n"
        "  <groupId>com.example</groupId>\n"
        "  <artifactId>parent</artifactId>\n"
        "  <version>1.0.0</version>\n"
        "  <packaging>pom</packaging>\n"
        "  <properties>\n"
        "    <log4j.version>2.14.1</log4j.version>\n"
        "  </properties>\n"
        "  <dependencyManagement>\n"
        "    <dependencies>\n"
        "      <dependency>\n"
        "        <groupId>org.apache.logging.log4j</groupId>\n"
        "        <artifactId>log4j-core</artifactId>\n"
        "        <version>${log4j.version}</version>\n"
        "      </dependency>\n"
        "    </dependencies>\n"
        "  </dependencyManagement>\n"
        "</project>\n"
    )


def _write_child_pom(path: Path, *, relative_path: str = "../pom.xml") -> None:
    path.write_text(
        "<project>\n"
        "  <parent>\n"
        "    <groupId>com.example</groupId>\n"
        "    <artifactId>parent</artifactId>\n"
        "    <version>1.0.0</version>\n"
        f"    <relativePath>{relative_path}</relativePath>\n"
        "  </parent>\n"
        "  <artifactId>service-a</artifactId>\n"
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>org.apache.logging.log4j</groupId>\n"
        "      <artifactId>log4j-core</artifactId>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n"
    )


def test_resolve_inherited_versions_fills_in_version_from_sibling_parent_pom(
    tmp_path: Path,
) -> None:
    """The real motivating case: a child declares a dependency with no
    <version> at all, inherited from a parent pom.xml that is genuinely
    present in the same scan (a true multi-module reactor layout)."""
    _write_parent_pom(tmp_path / "pom.xml")
    (tmp_path / "service-a").mkdir()
    _write_child_pom(tmp_path / "service-a" / "pom.xml")

    parent_result = parse_pom_file(tmp_path / "pom.xml")
    child_result = parse_pom_file(tmp_path / "service-a" / "pom.xml")
    assert child_result.dependencies[0].version is None  # unresolved before the fix

    resolved = resolve_inherited_versions((parent_result, child_result))
    resolved_child = next(pom for pom in resolved if pom.path == child_result.path)

    assert resolved_child.dependencies[0].version == "2.14.1"
    assert (
        resolved_child.dependencies[0].raw_version is None
    )  # the literal declaration is unchanged


def test_resolve_inherited_versions_does_nothing_when_parent_is_not_in_the_scan(
    tmp_path: Path,
) -> None:
    """The common real case (spring-petclinic-rest, quarkus-super-heroes):
    the parent is a third-party BOM, not a sibling file - must degrade to
    exactly the pre-fix behavior (unresolved, not a guess), never crash."""
    (tmp_path / "service-a").mkdir()
    _write_child_pom(tmp_path / "service-a" / "pom.xml")
    child_result = parse_pom_file(tmp_path / "service-a" / "pom.xml")

    resolved = resolve_inherited_versions((child_result,))

    assert resolved == (child_result,)
    assert resolved[0].dependencies[0].version is None


def test_resolve_inherited_versions_respects_explicitly_empty_relative_path(
    tmp_path: Path,
) -> None:
    """An explicit empty <relativePath/> is Maven's own marker for "never
    resolve this parent locally" - must not fall back to the default
    ../pom.xml guess, even when a file happens to exist there."""
    _write_parent_pom(tmp_path / "pom.xml")
    (tmp_path / "service-a").mkdir()
    _write_child_pom(tmp_path / "service-a" / "pom.xml", relative_path="")

    parent_result = parse_pom_file(tmp_path / "pom.xml")
    child_result = parse_pom_file(tmp_path / "service-a" / "pom.xml")

    resolved = resolve_inherited_versions((parent_result, child_result))
    resolved_child = next(pom for pom in resolved if pom.path == child_result.path)

    assert resolved_child.dependencies[0].version is None


def test_resolve_inherited_versions_walks_a_multi_level_chain(tmp_path: Path) -> None:
    """A grandparent's <dependencyManagement> must be reachable through an
    intermediate parent that declares no matching entry of its own.

    ``service-a``'s own <parent> block declares its genuine immediate
    parent ("middle"), not the grandparent directly - each hop's declared
    coordinates must match the POM actually found at that hop's
    <relativePath>, exactly as real Maven itself requires."""
    _write_parent_pom(tmp_path / "pom.xml")  # grandparent: declares log4j-core
    (tmp_path / "middle").mkdir()
    (tmp_path / "middle" / "pom.xml").write_text(
        "<project>\n"
        "  <parent>\n"
        "    <groupId>com.example</groupId>\n"
        "    <artifactId>parent</artifactId>\n"
        "    <version>1.0.0</version>\n"
        "  </parent>\n"
        "  <artifactId>middle</artifactId>\n"
        "  <packaging>pom</packaging>\n"
        "</project>\n"
    )
    (tmp_path / "middle" / "service-a").mkdir()
    (tmp_path / "middle" / "service-a" / "pom.xml").write_text(
        "<project>\n"
        "  <parent>\n"
        "    <groupId>com.example</groupId>\n"
        "    <artifactId>middle</artifactId>\n"
        "    <version>1.0.0</version>\n"
        "    <relativePath>../pom.xml</relativePath>\n"
        "  </parent>\n"
        "  <artifactId>service-a</artifactId>\n"
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>org.apache.logging.log4j</groupId>\n"
        "      <artifactId>log4j-core</artifactId>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n"
    )

    poms = (
        parse_pom_file(tmp_path / "pom.xml"),
        parse_pom_file(tmp_path / "middle" / "pom.xml"),
        parse_pom_file(tmp_path / "middle" / "service-a" / "pom.xml"),
    )
    resolved = resolve_inherited_versions(poms)
    resolved_child = next(pom for pom in resolved if "service-a" in pom.path.parts)

    assert resolved_child.dependencies[0].version == "2.14.1"


def test_resolve_inherited_versions_detects_a_parent_cycle_without_hanging(
    tmp_path: Path,
) -> None:
    """Adversarial input: two POMs declaring each other as parent must not
    infinite-loop - this parses untrusted pom.xml content."""
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "pom.xml").write_text(
        "<project>\n"
        "  <parent>\n"
        "    <groupId>com.example</groupId>\n"
        "    <artifactId>b</artifactId>\n"
        "    <version>1.0.0</version>\n"
        "    <relativePath>../b/pom.xml</relativePath>\n"
        "  </parent>\n"
        "  <artifactId>a</artifactId>\n"
        "</project>\n"
    )
    (tmp_path / "b" / "pom.xml").write_text(
        "<project>\n"
        "  <parent>\n"
        "    <groupId>com.example</groupId>\n"
        "    <artifactId>a</artifactId>\n"
        "    <version>1.0.0</version>\n"
        "    <relativePath>../a/pom.xml</relativePath>\n"
        "  </parent>\n"
        "  <artifactId>b</artifactId>\n"
        "</project>\n"
    )

    poms = (parse_pom_file(tmp_path / "a" / "pom.xml"), parse_pom_file(tmp_path / "b" / "pom.xml"))

    resolved = resolve_inherited_versions(poms)  # must return, not hang

    assert len(resolved) == 2


def _write_parent_chain(root: Path, depth: int) -> Path:
    """Build a nested chain of ``depth`` + 1 POMs (``level0`` at ``root``
    down to ``level{depth}``, each a subdirectory of the previous), where
    only ``level0`` declares the real ``dependencyManagement`` entry and
    ``level{depth}`` is the leaf with the unresolved dependency. Returns
    the leaf POM's path. Reaching ``level0`` from the leaf takes exactly
    ``depth`` hops - the same measure ``_MAX_PARENT_CHAIN_DEPTH`` bounds.
    """
    current = root
    current.mkdir(parents=True, exist_ok=True)
    (current / "pom.xml").write_text(
        "<project>\n"
        "  <groupId>com.example</groupId>\n"
        "  <artifactId>level0</artifactId>\n"
        "  <version>1.0.0</version>\n"
        "  <dependencyManagement>\n"
        "    <dependencies>\n"
        "      <dependency>\n"
        "        <groupId>org.apache.logging.log4j</groupId>\n"
        "        <artifactId>log4j-core</artifactId>\n"
        "        <version>2.14.1</version>\n"
        "      </dependency>\n"
        "    </dependencies>\n"
        "  </dependencyManagement>\n"
        "</project>\n"
    )
    for level in range(1, depth + 1):
        current = current / f"level{level}"
        current.mkdir()
        is_leaf = level == depth
        body = (
            "  <dependencies>\n"
            "    <dependency>\n"
            "      <groupId>org.apache.logging.log4j</groupId>\n"
            "      <artifactId>log4j-core</artifactId>\n"
            "    </dependency>\n"
            "  </dependencies>\n"
            if is_leaf
            else ""
        )
        current_artifact_id = f"level{level}"
        parent_artifact_id = f"level{level - 1}"
        (current / "pom.xml").write_text(
            "<project>\n"
            "  <parent>\n"
            "    <groupId>com.example</groupId>\n"
            f"    <artifactId>{parent_artifact_id}</artifactId>\n"
            "    <version>1.0.0</version>\n"
            "    <relativePath>../pom.xml</relativePath>\n"
            "  </parent>\n"
            f"  <artifactId>{current_artifact_id}</artifactId>\n"
            f"{body}"
            "</project>\n"
        )
    return current / "pom.xml"


def test_resolve_inherited_versions_resolves_at_exactly_the_depth_cap(tmp_path: Path) -> None:
    """A chain exactly ``_MAX_PARENT_CHAIN_DEPTH`` (10) hops deep must
    still resolve - confirms the cap's boundary is inclusive, not
    off-by-one in the restrictive direction."""
    leaf_path = _write_parent_chain(tmp_path / "chain10", depth=10)
    poms = tuple(parse_pom_file(p) for p in sorted((tmp_path / "chain10").glob("**/pom.xml")))

    resolved = resolve_inherited_versions(poms)
    resolved_leaf = next(pom for pom in resolved if pom.path == leaf_path.resolve())

    assert resolved_leaf.dependencies[0].version == "2.14.1"


def test_resolve_inherited_versions_stays_unresolved_past_the_depth_cap(tmp_path: Path) -> None:
    """A chain one hop past ``_MAX_PARENT_CHAIN_DEPTH`` must stay honestly
    unresolved rather than walking arbitrarily far, and must still
    terminate promptly rather than hang - this indexes untrusted,
    AI-generated monorepo structures that could plausibly nest this
    deep by accident."""
    leaf_path = _write_parent_chain(tmp_path / "chain11", depth=11)
    poms = tuple(parse_pom_file(p) for p in sorted((tmp_path / "chain11").glob("**/pom.xml")))

    resolved = resolve_inherited_versions(poms)
    resolved_leaf = next(pom for pom in resolved if pom.path == leaf_path.resolve())

    assert resolved_leaf.dependencies[0].version is None


def test_resolve_inherited_versions_prefers_a_resolved_version_over_the_nearest_match(
    tmp_path: Path,
) -> None:
    """A deliberate, documented simplification: if the nearest ancestor's
    managed entry doesn't itself resolve, search further up rather than
    stopping at Maven's strict nearest-wins answer - maximizing successful
    resolution over exact fidelity in this rarer disagreement case."""
    (tmp_path / "grandparent.xml").write_text(
        "<project>\n"
        "  <groupId>com.example</groupId>\n"
        "  <artifactId>grandparent</artifactId>\n"
        "  <version>1.0.0</version>\n"
        "  <dependencyManagement>\n"
        "    <dependencies>\n"
        "      <dependency>\n"
        "        <groupId>org.apache.logging.log4j</groupId>\n"
        "        <artifactId>log4j-core</artifactId>\n"
        "        <version>2.14.1</version>\n"
        "      </dependency>\n"
        "    </dependencies>\n"
        "  </dependencyManagement>\n"
        "</project>\n"
    )
    (tmp_path / "pom.xml").write_text(
        "<project>\n"
        "  <parent>\n"
        "    <groupId>com.example</groupId>\n"
        "    <artifactId>grandparent</artifactId>\n"
        "    <version>1.0.0</version>\n"
        "    <relativePath>grandparent.xml</relativePath>\n"
        "  </parent>\n"
        "  <artifactId>parent</artifactId>\n"
        "  <dependencyManagement>\n"
        "    <dependencies>\n"
        "      <dependency>\n"
        "        <groupId>org.apache.logging.log4j</groupId>\n"
        "        <artifactId>log4j-core</artifactId>\n"
        "        <version>${undeclared.property}</version>\n"
        "      </dependency>\n"
        "    </dependencies>\n"
        "  </dependencyManagement>\n"
        "</project>\n"
    )
    (tmp_path / "service-a").mkdir()
    _write_child_pom(tmp_path / "service-a" / "pom.xml")

    poms = (
        parse_pom_file(tmp_path / "grandparent.xml"),
        parse_pom_file(tmp_path / "pom.xml"),
        parse_pom_file(tmp_path / "service-a" / "pom.xml"),
    )
    resolved = resolve_inherited_versions(poms)
    resolved_child = next(pom for pom in resolved if "service-a" in pom.path.parts)

    assert resolved_child.dependencies[0].version == "2.14.1"


# -- Parent identity verification --------------------------------------------
#
# Found by independent QA of the reactor-POM fix: _walk_parent_chain used to
# trust whatever POM sat at the resolved <relativePath>, without checking it
# actually matched the declared <parent> coordinates. A typo'd or
# restructured relativePath in untrusted, AI-generated input could then
# silently borrow an unrelated module's managed version - functionally
# worse than staying honestly unresolved, since this feature's whole design
# philosophy is "never guess past what's genuinely present in the scan."


def test_resolve_inherited_versions_rejects_a_relative_path_pointing_at_the_wrong_module(
    tmp_path: Path,
) -> None:
    """A <relativePath> that resolves to a POM with different coordinates
    than the declared <parent> must not be trusted, even though a file does
    exist at that position - real Maven itself falls back to repository
    resolution in this situation rather than using the mismatched file."""
    (tmp_path / "pom.xml").write_text(
        "<project>\n"
        "  <groupId>org.unrelated</groupId>\n"
        "  <artifactId>unrelated-project</artifactId>\n"
        "  <version>9.9.9</version>\n"
        "  <dependencyManagement>\n"
        "    <dependencies>\n"
        "      <dependency>\n"
        "        <groupId>org.apache.logging.log4j</groupId>\n"
        "        <artifactId>log4j-core</artifactId>\n"
        "        <version>2.14.1</version>\n"
        "      </dependency>\n"
        "    </dependencies>\n"
        "  </dependencyManagement>\n"
        "</project>\n"
    )
    (tmp_path / "service-a").mkdir()
    _write_child_pom(tmp_path / "service-a" / "pom.xml")  # declares parent "com.example:parent"

    poms = (
        parse_pom_file(tmp_path / "pom.xml"),
        parse_pom_file(tmp_path / "service-a" / "pom.xml"),
    )
    resolved = resolve_inherited_versions(poms)
    resolved_child = next(pom for pom in resolved if "service-a" in pom.path.parts)

    assert resolved_child.dependencies[0].version is None


def test_resolve_inherited_versions_accepts_a_candidate_that_inherits_its_own_group_id(
    tmp_path: Path,
) -> None:
    """A candidate parent POM that itself omits <groupId>/<version> (legal
    Maven - inherited from its own parent) must still be accepted when its
    <artifactId> matches, rather than rejected for merely lacking fields
    the child's <parent> block happens to also (redundantly) restate."""
    _write_parent_pom(tmp_path / "pom.xml")  # grandparent: declares log4j-core
    (tmp_path / "middle").mkdir()
    (tmp_path / "middle" / "pom.xml").write_text(
        "<project>\n"
        "  <parent>\n"
        "    <groupId>com.example</groupId>\n"
        "    <artifactId>parent</artifactId>\n"
        "    <version>1.0.0</version>\n"
        "  </parent>\n"
        "  <artifactId>middle</artifactId>\n"  # own groupId/version inherited, not restated
        "  <packaging>pom</packaging>\n"
        "</project>\n"
    )
    (tmp_path / "middle" / "service-a").mkdir()
    (tmp_path / "middle" / "service-a" / "pom.xml").write_text(
        "<project>\n"
        "  <parent>\n"
        "    <groupId>com.example</groupId>\n"
        "    <artifactId>middle</artifactId>\n"
        "    <version>1.0.0</version>\n"
        "    <relativePath>../pom.xml</relativePath>\n"
        "  </parent>\n"
        "  <artifactId>service-a</artifactId>\n"
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>org.apache.logging.log4j</groupId>\n"
        "      <artifactId>log4j-core</artifactId>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n"
    )

    poms = (
        parse_pom_file(tmp_path / "pom.xml"),
        parse_pom_file(tmp_path / "middle" / "pom.xml"),
        parse_pom_file(tmp_path / "middle" / "service-a" / "pom.xml"),
    )
    resolved = resolve_inherited_versions(poms)
    resolved_child = next(pom for pom in resolved if "service-a" in pom.path.parts)

    # Resolution reaches past "middle" (which itself omits groupId/version)
    # to the grandparent's managed version - the soft group_id/version check
    # doesn't block a legitimately-matching but identity-omitting candidate.
    assert resolved_child.dependencies[0].version == "2.14.1"


def test_parse_extracts_the_pom_s_own_project_identity(tmp_path: Path) -> None:
    pom = tmp_path / "pom.xml"
    _write_parent_pom(pom)

    result = parse_pom_file(pom)

    assert result.group_id == "com.example"
    assert result.artifact_id == "parent"
    assert result.version == "1.0.0"
