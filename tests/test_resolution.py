"""Resolution: addresses, functions (read and write modes), symbols, data types."""

import pytest

from ghidra_mcp.errors import FIX_INPUT, classify
from ghidra_mcp.tools import ResolutionMode
from tests.program_fakes import (
    Addr,
    DataType,
    FakeProgram,
    Function,
    Symbol,
    install_cparser,
    tools_for,
)

READ, WRITE = ResolutionMode.READ, ResolutionMode.WRITE

EXT_PRINTF = Function("printf", Addr(0x10, "EXTERNAL"), namespace="<EXTERNAL>", external=True)


@pytest.fixture
def tools():
    program = FakeProgram(
        functions=[
            Function("main", 0x401000),
            Function("add", 0x401100),
            Function("bar", 0x401200, namespace="Foo"),
            Function("baz", 0x401300, namespace="Foo"),
            Function("dup", 0x401400, namespace="A"),
            Function("dup", 0x401500, namespace="B"),
            Function("printf", 0x401600, thunk_of=EXT_PRINTF),
            EXT_PRINTF,
            Function("cafe", 0x401700),
            Function("FUN_0000c000", 0xC000, size=0x1000),
            Function("parse_header", 0x401800),
            Function("parse_body", 0x401900),
            Function("init_engine", 0x401A00),
            Function("domain_check", 0x401B00),
            Function("Twin", 0x401C00),
            Function("twin", 0x401D00),
        ],
        symbols=[
            Symbol("g_config", 0x404000, source="USER_DEFINED"),
            Symbol("DAT_00404100", 0x404100, dynamic=True),
            Symbol("config_table", 0x404200),
            Symbol("g_config_backup", 0x404300),
            Symbol("alias_one", 0x404400),
            Symbol("alias_two", 0x404400),
            Symbol("tmp", 0x404600),
            Symbol("tmp", 0x404700),
            Symbol("beef", 0x404900),
        ],
        memory=[(0x400000, 0x10000), (0xB000, 0x2000)],
    )
    return tools_for(program)


def _fails(call, *fragments):
    with pytest.raises(ValueError) as raised:
        call()
    message = str(raised.value)
    for fragment in fragments:
        assert fragment in message, message
    return message


# ── Address parsing ──────────────────────────────────────────────────────────


# @spec RES-001
@pytest.mark.parametrize("text", ["401000", "0x401000", "0X401000"])
def test_addresses_parse_with_or_without_0x(tools, text):
    assert tools._parse_address(text) == Addr(0x401000)


# @spec RES-002
def test_an_unparseable_address_names_the_value(tools):
    _fails(lambda: tools._parse_address("zzz"), "zzz")


# ── Functions ────────────────────────────────────────────────────────────────


# @spec RES-003
@pytest.mark.parametrize("mode", [READ, WRITE])
def test_an_entry_point_address_resolves_in_either_mode(tools, mode):
    resolved = tools.resolve_function("0x401000", mode)
    assert resolved.target.getName() == "main" and resolved.note is None


# @spec RES-004
@pytest.mark.parametrize("mode", [READ, WRITE])
def test_an_exact_qualified_name_resolves_case_insensitively(tools, mode):
    assert tools.resolve_function("MAIN", mode).target.getName() == "main"  # despite domain_check
    resolved = tools.resolve_function("foo::BAR", mode)
    assert str(resolved.target) == "Foo::bar" and resolved.note is None


# @spec RES-005
@pytest.mark.parametrize("mode", [READ, WRITE])
def test_several_exact_matches_are_ambiguous(tools, mode):
    _fails(lambda: tools.resolve_function("twin", mode), "Ambiguous", "Twin @ 00401c00", "twin @ 00401d00")


# @spec RES-006
def test_write_mode_refuses_partial_matches_with_candidates(tools):
    _fails(lambda: tools.resolve_function("engine", WRITE), "not found", "init_engine @ 00401a00")
    _fails(lambda: tools.resolve_function("parse", WRITE), "parse_header @ 00401800", "parse_body @ 00401900")


# @spec RES-007
@pytest.mark.parametrize("mode", [READ, WRITE])
def test_no_match_is_not_found(tools, mode):
    _fails(lambda: tools.resolve_function("nothing_like_it", mode), "'nothing_like_it' not found")


# @spec RES-018
def test_read_mode_resolves_a_unique_partial_match_and_discloses_it(tools):
    resolved = tools.resolve_function("engine", READ)
    assert resolved.target.getName() == "init_engine"
    assert resolved.note == "'engine' resolved to init_engine @ 00401a00 (partial name match)"
    assert str(tools.resolve_function("bar", READ).target) == "Foo::bar"  # a plain name in a namespace


# @spec RES-018
def test_read_mode_with_several_partial_matches_lists_them(tools):
    _fails(lambda: tools.resolve_function("parse", READ), "parse_header @ 00401800", "parse_body @ 00401900")


# @spec RES-020
def test_read_mode_resolves_an_address_inside_a_function_and_discloses_it(tools):
    resolved = tools.resolve_function("0x401010", READ)
    assert resolved.target.getName() == "main"
    assert resolved.note == "'0x401010' resolved to main @ 00401000 (address inside the function)"


# @spec RES-021
def test_write_mode_requires_an_entry_point_address(tools):
    _fails(lambda: tools.resolve_function("0x401010", WRITE), "entry-point", "main @ 00401000")
    _fails(lambda: tools.resolve_function("0x40f000", WRITE), "entry-point")


# @spec RES-022
@pytest.mark.parametrize("mode", [READ, WRITE])
def test_an_address_and_a_name_that_disagree_fail_listing_both(tools, mode):
    _fails(lambda: tools.resolve_function("cafe", mode), "cafe @ 00401700", "FUN_0000c000 @ 0000c000")


# @spec RES-022
@pytest.mark.parametrize("mode", [READ, WRITE])
def test_a_hex_looking_name_resolves_by_name_when_no_function_is_at_that_address(tools, mode):
    assert tools.resolve_function("add", mode).target.getName() == "add"


# @spec RES-025
def test_write_mode_refuses_thunks_and_externals(tools):
    _fails(lambda: tools.resolve_function("printf", WRITE), "thunk", "<EXTERNAL>::printf")
    _fails(lambda: tools.resolve_function("<EXTERNAL>::printf", WRITE), "external")


# @spec RES-025
def test_read_mode_resolves_thunks_and_externals(tools):
    assert tools.resolve_function("printf", READ).target.isThunk()
    assert tools.resolve_function("<EXTERNAL>::printf", READ).target.isExternal()


def test_find_function_is_write_mode(tools):
    assert tools.find_function("main").getName() == "main"
    with pytest.raises(ValueError):
        tools.find_function("engine")


# ── Cross-reference targets (single symbol or address) ───────────────────────


# @spec RES-008
def test_an_exact_symbol_name_wins_over_names_containing_it(tools):
    resolved = tools.resolve_reference_target("G_CONFIG")
    assert resolved.target == Addr(0x404000) and resolved.note is None


# @spec RES-009
def test_several_partial_symbol_matches_list_the_candidates(tools):
    _fails(lambda: tools.resolve_reference_target("config_"), "config_table @ 00404200", "g_config_backup @ 00404300")


# @spec RES-010
def test_several_exact_symbol_matches_at_different_addresses_are_ambiguous(tools):
    _fails(lambda: tools.resolve_reference_target("tmp"), "Ambiguous", "tmp @ 00404600", "tmp @ 00404700")


# @spec RES-011
def test_an_unknown_symbol_is_not_found(tools):
    _fails(lambda: tools.resolve_reference_target("zz_nothing"), "'zz_nothing' not found")


# @spec RES-012
@pytest.mark.parametrize("text", ["0x404400", "0x404800"])  # two symbols there; none there
def test_an_address_is_its_own_reference_target(tools, text):
    resolved = tools.resolve_reference_target(text)
    assert resolved.target == tools._parse_address(text) and resolved.note is None


# @spec RES-019
def test_a_unique_partial_symbol_match_is_resolved_and_disclosed(tools):
    resolved = tools.resolve_reference_target("backup")
    assert resolved.target == Addr(0x404300)
    assert resolved.note == "'backup' resolved to g_config_backup @ 00404300 (partial name match)"


# @spec RES-026
def test_dynamic_symbols_resolve_by_name(tools):
    assert tools.resolve_reference_target("DAT_00404100").target == Addr(0x404100)


# @spec RES-022
def test_a_reference_target_that_is_both_an_address_and_a_different_name_fails(tools):
    _fails(lambda: tools.resolve_reference_target("beef"), "beef @ 00404900", "0000beef")


# ── Symbol search ────────────────────────────────────────────────────────────


def _names(symbols):
    return sorted(s.getName(True) for s in symbols)


# @spec RES-013
def test_symbol_search_matches_names_including_externals_and_dynamic_symbols(tools):
    assert _names(tools._lookup_symbols("config")) == ["config_table", "g_config", "g_config_backup"]
    assert _names(tools._lookup_symbols("dat_")) == ["DAT_00404100"]
    assert _names(tools._lookup_symbols("printf")) == ["<EXTERNAL>::printf", "printf"]


# @spec RES-013
def test_symbol_search_includes_the_symbols_at_an_address_query(tools):
    assert _names(tools._lookup_symbols("404400")) == ["alias_one", "alias_two"]


# ── Data types ───────────────────────────────────────────────────────────────


def _dt_tools(monkeypatch, types_, parse):
    install_cparser(monkeypatch, parse)
    return tools_for(FakeProgram(data_types=types_))


def _parse_error(text):
    raise RuntimeError("parse error")


# @spec RES-014
def test_type_resolution_tries_lookup_then_parse_then_name_scan(monkeypatch):
    int_t, ptr_t, mine = DataType("int"), DataType("char *"), DataType("MyStruct", "/mine")
    tools = _dt_tools(monkeypatch, [int_t, mine], lambda text: ptr_t if text.startswith("char *") else _parse_error(text))
    assert tools._resolve_data_type("/int") is int_t
    assert tools._resolve_data_type("char *") is ptr_t
    assert tools._resolve_data_type("MyStruct") is mine


# @spec RES-015
def test_an_unresolvable_type_names_the_type_string(monkeypatch):
    tools = _dt_tools(monkeypatch, [], _parse_error)
    _fails(lambda: tools._resolve_data_type("NoSuchType"), "'NoSuchType'")


# @spec RES-023
def test_same_named_types_in_different_categories_are_ambiguous(monkeypatch):
    tools = _dt_tools(monkeypatch, [DataType("HANDLE", "/winnt.h"), DataType("HANDLE", "/other.h")], _parse_error)
    _fails(lambda: tools._resolve_data_type("HANDLE"), "/winnt.h/HANDLE", "/other.h/HANDLE")


# @spec RES-024
def test_a_declaration_that_parses_to_nothing_fails(monkeypatch):
    tools = _dt_tools(monkeypatch, [DataType("weird")], lambda text: None)
    _fails(lambda: tools._resolve_data_type("weird"), "'weird'")


# ── Listings and the error contract ──────────────────────────────────────────


# @spec RES-016
def test_listing_without_externals_excludes_thunks_and_externals(tools):
    without = {str(f) for f in tools.get_all_functions(include_externals=False)}
    with_ = {str(f) for f in tools.get_all_functions(include_externals=True)}
    assert "printf" not in without and "<EXTERNAL>::printf" not in without
    assert {"printf", "<EXTERNAL>::printf"} <= with_


# @spec RES-017
@pytest.mark.parametrize(
    "call",
    [
        lambda t: t._parse_address("zzz"),
        lambda t: t.resolve_function("nothing_like_it", READ),
        lambda t: t.resolve_function("printf", WRITE),
        lambda t: t.resolve_reference_target("tmp"),
    ],
)
def test_every_resolution_failure_is_fix_input(tools, call):
    with pytest.raises(ValueError) as raised:
        call(tools)
    assert classify(raised.value) == FIX_INPUT
