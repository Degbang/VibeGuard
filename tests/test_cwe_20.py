"""Tests for vibeguard.layer1_static.rules.cwe_20."""

from __future__ import annotations

from pathlib import Path

from vibeguard.layer1_static.ast_parser import ParsedFile, parse_file
from vibeguard.layer1_static.rules._interface_annotations import (
    InterfaceMethodAnnotations,
    InterfaceParameterAnnotations,
    build_interface_hierarchy_index,
    build_interface_method_index,
    build_interface_parameter_index,
)
from vibeguard.layer1_static.rules.cwe_20 import CWE_ID, detect_in_java

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_detect_in_java_finds_unvalidated_request_body() -> None:
    result = parse_file(FIXTURES_DIR / "UnvalidatedRequestBody.java")

    findings = detect_in_java(result)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.cwe_id == CWE_ID
    assert finding.identifier == "dto"
    assert finding.line == 13


def test_detect_in_java_does_not_flag_valid_annotated_body() -> None:
    result = parse_file(FIXTURES_DIR / "UnvalidatedRequestBody.java")

    identifiers_by_line = {f.line: f.identifier for f in detect_in_java(result)}

    assert 18 not in identifiers_by_line


def test_detect_in_java_does_not_flag_string_body() -> None:
    """A String body has no bean fields for @Valid to cascade into."""
    result = parse_file(FIXTURES_DIR / "UnvalidatedRequestBody.java")

    lines = {f.line for f in detect_in_java(result)}

    assert 23 not in lines


def test_detect_in_java_does_not_flag_non_request_body_parameter() -> None:
    result = parse_file(FIXTURES_DIR / "UnvalidatedRequestBody.java")

    identifiers = {f.identifier for f in detect_in_java(result)}

    assert "id" not in identifiers


def test_detect_in_java_does_not_flag_non_endpoint_method() -> None:
    result = parse_file(FIXTURES_DIR / "UnvalidatedRequestBody.java")

    findings = detect_in_java(result)

    assert len(findings) == 1  # only the one true positive, helper() ignored


def test_detect_in_java_recognizes_validated_annotation(tmp_path: Path) -> None:
    """@Validated is an accepted alternative to @Valid."""
    java_file = tmp_path / "Foo.java"
    java_file.write_text(
        "@RestController\n"
        "public class Foo {\n"
        '    @PostMapping("/x")\n'
        "    public void m(@Validated @RequestBody Dto dto) {}\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert detect_in_java(result) == ()


def test_detect_in_java_recognizes_fully_qualified_annotations(tmp_path: Path) -> None:
    java_file = tmp_path / "Foo.java"
    java_file.write_text(
        "@RestController\n"
        "public class Foo {\n"
        '    @PostMapping("/x")\n'
        "    public void m(@javax.validation.Valid "
        "@org.springframework.web.bind.annotation.RequestBody Dto dto) {}\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert detect_in_java(result) == ()


def test_detect_in_java_finds_endpoint_inside_nested_class(tmp_path: Path) -> None:
    """Same nested-class coverage cwe_284.py needed - walked the raw tree from the start."""
    java_file = tmp_path / "Outer.java"
    java_file.write_text(
        "public class Outer {\n"
        "    public static class Inner {\n"
        '        @PostMapping("/x")\n'
        "        public void m(@RequestBody Dto dto) {}\n"
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    findings = detect_in_java(result)
    assert len(findings) == 1
    assert findings[0].identifier == "dto"


def test_detect_in_java_judges_multiple_parameters_independently(tmp_path: Path) -> None:
    java_file = tmp_path / "Foo.java"
    java_file.write_text(
        "@RestController\n"
        "public class Foo {\n"
        '    @PostMapping("/x")\n'
        "    public void m(@Valid @RequestBody GoodDto good, @RequestBody BadDto bad) {}\n"
        "}\n"
    )

    result = parse_file(java_file)

    findings = detect_in_java(result)
    assert len(findings) == 1
    assert findings[0].identifier == "bad"


def test_detect_in_java_finds_nothing_in_clean_file() -> None:
    result = parse_file(FIXTURES_DIR / "CleanService.java")

    assert detect_in_java(result) == ()


def test_detect_in_java_handles_missing_tree_gracefully() -> None:
    malformed = parse_file(FIXTURES_DIR / "MalformedService.java")

    assert malformed.tree is None
    assert detect_in_java(malformed) == ()


def test_detect_in_java_finds_unvalidated_body_with_modern_switch(tmp_path: Path) -> None:
    """Tree-sitter fallback files must still feed CWE-20."""
    java_file = tmp_path / "ModernBody.java"
    java_file.write_text(
        "import org.springframework.web.bind.annotation.*;\n"
        "@RestController\n"
        "public class ModernBody {\n"
        '    @PostMapping("/orders")\n'
        "    public String create(@RequestBody OrderDto dto, int level) {\n"
        "        return switch (level) {\n"
        '            case 1 -> "priority";\n'
        '            default -> "normal";\n'
        "        };\n"
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert result.tree_sitter is not None
    findings = detect_in_java(result)
    assert [(f.identifier, f.line) for f in findings] == [("dto", 4)]


# -- Interface-inherited annotation resolution -------------------------------
#
# Mirrors cwe_284.py's equivalent gap one level down: a concrete class
# implementing a codegen-style interface can carry the real routing/body/
# validation annotations only on the interface's method/parameters, with
# the @Override carrying none of its own.

_OWNERS_API_NO_VALID_JAVA = (
    "import org.springframework.web.bind.annotation.PutMapping;\n"
    "import org.springframework.web.bind.annotation.RequestBody;\n"
    "public interface OwnersApi {\n"
    '    @PutMapping("/owners/{id}")\n'
    "    void updateOwner(int id, @RequestBody Owner owner);\n"
    "}\n"
)

_OWNERS_API_WITH_VALID_JAVA = (
    "import org.springframework.web.bind.annotation.PutMapping;\n"
    "import org.springframework.web.bind.annotation.RequestBody;\n"
    "import javax.validation.Valid;\n"
    "public interface OwnersApi {\n"
    '    @PutMapping("/owners/{id}")\n'
    "    void updateOwner(int id, @Valid @RequestBody Owner owner);\n"
    "}\n"
)


def _build_indexes(
    *parsed_files: ParsedFile,
) -> tuple[InterfaceMethodAnnotations, InterfaceParameterAnnotations]:
    return (
        build_interface_method_index(parsed_files),
        build_interface_parameter_index(parsed_files),
    )


def test_detect_in_java_finds_unvalidated_body_inherited_from_interface(
    tmp_path: Path,
) -> None:
    """A concrete @Override with no annotations of its own must still be
    checked when the interface it implements declares @RequestBody on the
    matching parameter - the exact real-world codegen-controller shape
    this was built for, one level down from cwe_284.py's method-level fix."""
    (tmp_path / "OwnersApi.java").write_text(_OWNERS_API_NO_VALID_JAVA)
    controller_file = tmp_path / "OwnerController.java"
    controller_file.write_text(
        "public class OwnerController implements OwnersApi {\n"
        "    @Override\n"
        "    public void updateOwner(int id, Owner owner) {}\n"
        "}\n"
    )
    interface_result = parse_file(tmp_path / "OwnersApi.java")
    controller_result = parse_file(controller_file)
    method_index, param_index = _build_indexes(interface_result, controller_result)

    # Without the indexes, the gap this fix targets reproduces exactly:
    # the method is invisible as an endpoint, so nothing is checked at all.
    assert detect_in_java(controller_result) == ()

    findings = detect_in_java(controller_result, method_index, param_index)

    assert len(findings) == 1
    assert findings[0].identifier == "owner"
    assert "interface" not in findings[0].message  # no caveat: interface has no @Valid either


# -- Multi-level interface-extends chains ------------------------------------
#
# Mirrors cwe_284.py's equivalent fix exactly: the interface-widening
# resolution above only ever checked the single directly-implemented
# interface. If that interface itself extends a further interface, with the
# real @RequestBody/@Valid declared on the grand-interface, it was invisible
# entirely - the same false-negative shape, one level down (parameters
# instead of methods).

_BASE_OWNERS_API_JAVA = (
    "import org.springframework.web.bind.annotation.PutMapping;\n"
    "import org.springframework.web.bind.annotation.RequestBody;\n"
    "public interface BaseOwnersApi {\n"
    '    @PutMapping("/owners/{id}")\n'
    "    void updateOwner(int id, @RequestBody Owner owner);\n"
    "}\n"
)

_OWNERS_API_EXTENDS_BASE_JAVA = "public interface OwnersApi extends BaseOwnersApi {\n}\n"


def test_detect_in_java_finds_unvalidated_body_inherited_through_a_two_level_interface_chain(
    tmp_path: Path,
) -> None:
    (tmp_path / "BaseOwnersApi.java").write_text(_BASE_OWNERS_API_JAVA)
    (tmp_path / "OwnersApi.java").write_text(_OWNERS_API_EXTENDS_BASE_JAVA)
    controller_file = tmp_path / "OwnerController.java"
    controller_file.write_text(
        "public class OwnerController implements OwnersApi {\n"
        "    @Override\n"
        "    public void updateOwner(int id, Owner owner) {}\n"
        "}\n"
    )
    parsed = (
        parse_file(tmp_path / "BaseOwnersApi.java"),
        parse_file(tmp_path / "OwnersApi.java"),
        parse_file(controller_file),
    )
    controller_result = parsed[2]
    method_index, param_index = _build_indexes(*parsed)
    hierarchy = build_interface_hierarchy_index(parsed)

    # Without the hierarchy index, only the directly-implemented interface
    # (OwnersApi, which declares nothing of its own) is checked.
    assert detect_in_java(controller_result, method_index, param_index) == ()

    findings = detect_in_java(controller_result, method_index, param_index, hierarchy)

    assert len(findings) == 1
    assert findings[0].identifier == "owner"


def test_detect_in_java_adds_caveat_when_interface_parameter_has_validation(
    tmp_path: Path,
) -> None:
    """An interface-declared @Valid on the matching parameter must NOT
    silently suppress the finding - whether Spring's argument resolvers
    actually see it depends on which Method object gets resolved, which
    is not visible to static analysis. The finding must still fire, with
    an honest caveat attached."""
    (tmp_path / "OwnersApi.java").write_text(_OWNERS_API_WITH_VALID_JAVA)
    controller_file = tmp_path / "OwnerController.java"
    controller_file.write_text(
        "public class OwnerController implements OwnersApi {\n"
        "    @Override\n"
        "    public void updateOwner(int id, Owner owner) {}\n"
        "}\n"
    )
    interface_result = parse_file(tmp_path / "OwnersApi.java")
    controller_result = parse_file(controller_file)
    method_index, param_index = _build_indexes(interface_result, controller_result)

    findings = detect_in_java(controller_result, method_index, param_index)

    assert len(findings) == 1
    assert "not visible to static analysis" in findings[0].message
    assert "@Valid" in findings[0].message


def test_detect_in_java_does_not_add_caveat_when_own_parameter_is_validated(
    tmp_path: Path,
) -> None:
    """Coverage from the concrete method/parameter's own annotations must
    still fully suppress the finding, with no interface-validation
    caveat attached, even when the interface separately also declares
    @RequestBody (without @Valid) on the same parameter."""
    (tmp_path / "OwnersApi.java").write_text(_OWNERS_API_NO_VALID_JAVA)
    controller_file = tmp_path / "OwnerController.java"
    controller_file.write_text(
        "import org.springframework.web.bind.annotation.RequestBody;\n"
        "import javax.validation.Valid;\n"
        "public class OwnerController implements OwnersApi {\n"
        "    @Override\n"
        "    public void updateOwner(int id, @Valid @RequestBody Owner owner) {}\n"
        "}\n"
    )
    interface_result = parse_file(tmp_path / "OwnersApi.java")
    controller_result = parse_file(controller_file)
    method_index, param_index = _build_indexes(interface_result, controller_result)

    assert detect_in_java(controller_result, method_index, param_index) == ()


def test_detect_in_java_matches_interface_parameters_by_position_not_name(
    tmp_path: Path,
) -> None:
    """An overriding method may rename its parameters relative to the
    interface (parameter names aren't part of the method contract) -
    resolution must still work by position."""
    (tmp_path / "OwnersApi.java").write_text(_OWNERS_API_NO_VALID_JAVA)
    controller_file = tmp_path / "OwnerController.java"
    controller_file.write_text(
        "public class OwnerController implements OwnersApi {\n"
        "    @Override\n"
        "    public void updateOwner(int ownerId, Owner payload) {}\n"
        "}\n"
    )
    interface_result = parse_file(tmp_path / "OwnersApi.java")
    controller_result = parse_file(controller_file)
    method_index, param_index = _build_indexes(interface_result, controller_result)

    findings = detect_in_java(controller_result, method_index, param_index)

    assert len(findings) == 1
    assert findings[0].identifier == "payload"


def test_detect_in_java_finds_unvalidated_body_inherited_from_interface_tree_sitter_fallback(
    tmp_path: Path,
) -> None:
    """The same interface-inherited resolution must hold when the
    concrete file takes the Tree-sitter fallback path."""
    (tmp_path / "OwnersApi.java").write_text(_OWNERS_API_NO_VALID_JAVA)
    controller_file = tmp_path / "OwnerController.java"
    controller_file.write_text(
        "public class OwnerController implements OwnersApi {\n"
        "    @Override\n"
        "    public void updateOwner(int id, Owner owner) {\n"
        "        int x = switch (id) {\n"
        "            case 1 -> 1;\n"
        "            default -> 0;\n"
        "        };\n"
        "    }\n"
        "}\n"
    )
    interface_result = parse_file(tmp_path / "OwnersApi.java")
    controller_result = parse_file(controller_file)
    assert controller_result.tree_sitter is not None
    method_index, param_index = _build_indexes(interface_result, controller_result)

    assert detect_in_java(controller_result) == ()
    findings = detect_in_java(controller_result, method_index, param_index)

    assert len(findings) == 1
    assert findings[0].identifier == "owner"
