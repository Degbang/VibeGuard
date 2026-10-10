"""Tests for vibeguard.layer1_static.gradle_parser."""

from __future__ import annotations

from pathlib import Path

from vibeguard.layer1_static._parsing_guards import ParseStatus
from vibeguard.layer1_static.gradle_parser import parse_gradle_file


def test_parse_extracts_groovy_string_literal_dependency(tmp_path: Path) -> None:
    gradle_file = tmp_path / "build.gradle"
    gradle_file.write_text(
        "dependencies {\n" '    implementation "org.apache.logging.log4j:log4j-core:2.14.1"\n' "}\n"
    )

    result = parse_gradle_file(gradle_file)

    assert result.status == ParseStatus.OK
    assert len(result.dependencies) == 1
    dependency = result.dependencies[0]
    assert dependency.group_id == "org.apache.logging.log4j"
    assert dependency.artifact_id == "log4j-core"
    assert dependency.version == "2.14.1"
    assert dependency.raw_version == "2.14.1"
    assert dependency.line == 2


def test_parse_extracts_kotlin_dsl_parenthesized_dependency(tmp_path: Path) -> None:
    gradle_file = tmp_path / "build.gradle.kts"
    gradle_file.write_text(
        'dependencies {\n    implementation("org.apache.logging.log4j:log4j-core:2.14.1")\n}\n'
    )

    result = parse_gradle_file(gradle_file)

    assert result.status == ParseStatus.OK
    assert len(result.dependencies) == 1
    assert result.dependencies[0].artifact_id == "log4j-core"
    assert result.dependencies[0].version == "2.14.1"


def test_parse_recognizes_every_standard_configuration_name(tmp_path: Path) -> None:
    gradle_file = tmp_path / "build.gradle"
    gradle_file.write_text(
        "dependencies {\n"
        '    implementation "a:b:1.0"\n'
        '    api "c:d:1.0"\n'
        '    compileOnly "e:f:1.0"\n'
        '    runtimeOnly "g:h:1.0"\n'
        '    testImplementation "i:j:1.0"\n'
        '    annotationProcessor "k:l:1.0"\n'
        '    compile "m:n:1.0"\n'
        '    testCompile "o:p:1.0"\n'
        "}\n"
    )

    result = parse_gradle_file(gradle_file)

    assert result.status == ParseStatus.OK
    assert {d.artifact_id for d in result.dependencies} == {
        "b",
        "d",
        "f",
        "h",
        "j",
        "l",
        "n",
        "p",
    }


def test_parse_does_not_confuse_compile_with_compile_only(tmp_path: Path) -> None:
    """A camelCase boundary means \\b correctly tells "compileOnly" apart
    from a bare "compile" match - both must be recognized as themselves,
    not collapsed into one or the other."""
    gradle_file = tmp_path / "build.gradle"
    gradle_file.write_text('dependencies {\n    compile "a:b:1.0"\n    compileOnly "c:d:2.0"\n}\n')

    result = parse_gradle_file(gradle_file)

    versions_by_artifact = {d.artifact_id: d.version for d in result.dependencies}
    assert versions_by_artifact == {"b": "1.0", "d": "2.0"}


def test_parse_treats_group_artifact_only_as_unresolved_version(tmp_path: Path) -> None:
    """A platform/BOM-managed dependency with no explicit version segment
    must resolve to version=None, never a guess - the same "unknown is
    not vulnerable" discipline pom_parser.py already applies."""
    gradle_file = tmp_path / "build.gradle"
    gradle_file.write_text(
        'dependencies {\n    implementation "org.springframework.boot:spring-boot-starter-web"\n}\n'
    )

    result = parse_gradle_file(gradle_file)

    assert len(result.dependencies) == 1
    assert result.dependencies[0].version is None
    assert result.dependencies[0].raw_version is None


def test_parse_treats_variable_interpolated_version_as_unresolved(tmp_path: Path) -> None:
    """A Groovy/Kotlin variable or string-interpolation reference for the
    version segment must never be passed through as if it were a real,
    comparable version - this was checked directly because CWE-1035's own
    version comparison would otherwise treat an unresolved "$x" as
    version "0", a real false-positive risk."""
    gradle_file = tmp_path / "build.gradle"
    gradle_file.write_text(
        "dependencies {\n"
        '    implementation "org.apache.logging.log4j:log4j-core:$log4jVersion"\n'
        '    api "com.fasterxml.jackson.core:jackson-databind:${jacksonVersion}"\n'
        "}\n"
    )

    result = parse_gradle_file(gradle_file)

    assert len(result.dependencies) == 2
    for dependency in result.dependencies:
        assert dependency.version is None
        assert dependency.raw_version is not None and dependency.raw_version.startswith("$")


def test_parse_handles_a_nested_block_inside_dependencies_without_truncating(
    tmp_path: Path,
) -> None:
    """A nested brace block (e.g. Gradle's dependency-constraints feature)
    inside dependencies{} must not be mistaken for the block's own closing
    brace - every declaration on both sides of the nested block must
    still be found."""
    gradle_file = tmp_path / "build.gradle"
    gradle_file.write_text(
        "dependencies {\n"
        '    implementation "a:b:1.0"\n'
        "    constraints {\n"
        '        implementation "c:d:2.0"\n'
        "    }\n"
        '    implementation "e:f:3.0"\n'
        "}\n"
    )

    result = parse_gradle_file(gradle_file)

    assert {d.artifact_id for d in result.dependencies} == {"b", "d", "f"}


def test_parse_finds_dependencies_in_more_than_one_block_without_double_counting(
    tmp_path: Path,
) -> None:
    """A second, separate dependencies{} block elsewhere in the file (e.g.
    inside an allprojects{} wrapper) must be found too, and the search
    resuming after each block's own closing brace must never re-match a
    literal "dependencies {" occurring a second time inside an
    already-extracted block."""
    gradle_file = tmp_path / "build.gradle"
    gradle_file.write_text(
        "allprojects {\n"
        "    dependencies {\n"
        '        implementation "a:b:1.0"\n'
        "    }\n"
        "}\n"
        "dependencies {\n"
        '    implementation "c:d:2.0"\n'
        "}\n"
    )

    result = parse_gradle_file(gradle_file)

    assert len(result.dependencies) == 2
    assert {d.artifact_id for d in result.dependencies} == {"b", "d"}


def test_parse_ignores_buildscript_classpath_dependencies(tmp_path: Path) -> None:
    """A buildscript{} block's classpath dependency (the Gradle plugin
    build-time classpath, not the application's own runtime/compile
    dependencies) must never be flagged as if it were one - "classpath"
    is deliberately not in the recognized configuration name list."""
    gradle_file = tmp_path / "build.gradle"
    gradle_file.write_text(
        "buildscript {\n"
        "    dependencies {\n"
        '        classpath "com.android.tools.build:gradle:8.0.0"\n'
        "    }\n"
        "}\n"
        "dependencies {\n"
        '    implementation "a:b:1.0"\n'
        "}\n"
    )

    result = parse_gradle_file(gradle_file)

    assert len(result.dependencies) == 1
    assert result.dependencies[0].artifact_id == "b"


def test_parse_ignores_version_catalog_accessor_with_no_string_literal(
    tmp_path: Path,
) -> None:
    """Version-catalog syntax (libs.versions.toml) has no string literal
    at all - this heuristic never claims to recognize it, and correctly
    finds nothing rather than mis-parsing it."""
    gradle_file = tmp_path / "build.gradle.kts"
    gradle_file.write_text("dependencies {\n    implementation(libs.log4j.core)\n}\n")

    result = parse_gradle_file(gradle_file)

    assert result.status == ParseStatus.OK
    assert result.dependencies == ()


def test_parse_ignores_a_project_reference(tmp_path: Path) -> None:
    """A same-repo module reference (project(":some-module")) is not a
    Maven coordinate and must never be mistaken for one."""
    gradle_file = tmp_path / "build.gradle"
    gradle_file.write_text('dependencies {\n    implementation project(":some-module")\n}\n')

    result = parse_gradle_file(gradle_file)

    assert result.dependencies == ()


def test_parse_empty_file_is_flagged_not_silently_ok(tmp_path: Path) -> None:
    gradle_file = tmp_path / "build.gradle"
    gradle_file.write_text("")

    result = parse_gradle_file(gradle_file)

    assert result.status == ParseStatus.EMPTY_FILE


def test_parse_file_too_large_is_rejected_before_reading(tmp_path: Path) -> None:
    gradle_file = tmp_path / "build.gradle"
    gradle_file.write_text('dependencies { implementation "a:b:1.0" }\n')

    result = parse_gradle_file(gradle_file, max_bytes=5)

    assert result.status == ParseStatus.FILE_TOO_LARGE


def test_parse_file_with_no_dependencies_block_is_ok_with_zero_dependencies(
    tmp_path: Path,
) -> None:
    gradle_file = tmp_path / "build.gradle"
    gradle_file.write_text("plugins {\n    id 'java'\n}\n")

    result = parse_gradle_file(gradle_file)

    assert result.status == ParseStatus.OK
    assert result.dependencies == ()


def test_parse_unbalanced_dependencies_block_stops_without_crashing(tmp_path: Path) -> None:
    """A malformed/truncated file with no matching closing brace must
    never raise - whatever was found before the unbalanced block is
    still returned, fail-closed rather than crashing the whole scan."""
    gradle_file = tmp_path / "build.gradle"
    gradle_file.write_text('dependencies {\n    implementation "a:b:1.0"\n')

    result = parse_gradle_file(gradle_file)

    assert result.status == ParseStatus.OK
    assert result.dependencies == ()
