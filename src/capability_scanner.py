from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Final, Sequence


@dataclass(frozen=True, slots=True)
class Token:
    text: str
    start_byte: int
    end_byte: int


@dataclass(frozen=True, slots=True)
class CallExpression:
    name: str
    arguments: tuple[tuple[Token, ...], ...]
    start_byte: int
    end_byte: int
    token_index: int
    result: tuple[Token, ...] | None
    receiver: str | None
    member: str | None
    accessor: str | None
    is_indirect: bool


@dataclass(frozen=True, slots=True)
class AssignmentCandidate:
    left: tuple[Token, ...]
    right: tuple[Token, ...]
    order_byte: int


@dataclass(frozen=True, slots=True)
class FieldCandidate:
    receiver_type: str
    receiver: str
    field: str
    value: tuple[Token, ...]
    order_byte: int


@dataclass(frozen=True, slots=True)
class ReturnCandidate:
    value: tuple[Token, ...]
    order_byte: int


@dataclass(frozen=True, slots=True)
class RegistrationCandidate:
    receiver_type: str
    receiver: str
    slot: str
    target_name: str
    tokens: tuple[Token, ...]


@dataclass(frozen=True, slots=True)
class ScannedSource:
    source_sha256: str
    tokens: tuple[Token, ...]
    calls: tuple[CallExpression, ...]
    assignments: tuple[AssignmentCandidate, ...]
    field_stores: tuple[FieldCandidate, ...]
    field_loads: tuple[FieldCandidate, ...]
    returns: tuple[ReturnCandidate, ...]
    registrations: tuple[RegistrationCandidate, ...]
    has_unsupported_syntax: bool
    unsupported_syntax_kinds: tuple[str, ...]
    identifier_symbols: frozenset[str]
    callback_symbols: frozenset[str]


_TOKEN: Final = re.compile(
    r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|"
    r"[A-Za-z_]\w*|0[xX][0-9A-Fa-f]+|\d+|->|&&|\|\||==|!=|<=|>=|!|"
    r"[.=&*(){}\[\],;#]",
    re.DOTALL,
)
_IDENTIFIER: Final = re.compile(r"[A-Za-z_]\w*")


def tokenize(source: str) -> tuple[Token, ...]:
    offsets = [0]
    for char in source:
        offsets.append(offsets[-1] + len(char.encode("utf-8")))
    return tuple(
        Token(match.group(), offsets[match.start()], offsets[match.end()])
        for match in _TOKEN.finditer(source)
        if not match.group().startswith(("//", "/*", "\"", "'"))
    )


def canonical(tokens: Sequence[Token]) -> str:
    return "".join(token.text for token in tokens)


def split_arguments(tokens: Sequence[Token]) -> tuple[tuple[Token, ...], ...]:
    if not tokens:
        return ()
    parts: list[tuple[Token, ...]] = []
    start = 0
    depth = 0
    for index, token in enumerate(tokens):
        if token.text in "([{":
            depth += 1
        elif token.text in ")]}":
            depth -= 1
        elif token.text == "," and depth == 0:
            parts.append(tuple(tokens[start:index]))
            start = index + 1
    parts.append(tuple(tokens[start:]))
    return tuple(parts)


def _expression_tail(tokens: Sequence[Token]) -> tuple[Token, ...]:
    if not tokens:
        return ()
    end = len(tokens)
    start = end - 1
    while start >= 2 and tokens[start - 1].text in {".", "->"}:
        start -= 2
    return tuple(tokens[start:end])


def _call_result(tokens: Sequence[Token], call_index: int) -> tuple[Token, ...] | None:
    start = call_index - 1
    while start >= 0 and tokens[start].text not in {";", "{"}:
        start -= 1
    equals = next((index for index in range(start + 1, call_index)
                   if tokens[index].text == "="), None)
    if equals is None:
        return None
    result = _expression_tail(tokens[start + 1:equals])
    return result or None


def find_calls(tokens: Sequence[Token]) -> tuple[CallExpression, ...]:
    found: list[CallExpression] = []
    for index, token in enumerate(tokens[:-1]):
        if _IDENTIFIER.fullmatch(token.text) is None or tokens[index + 1].text != "(":
            continue
        depth = 1
        end = index + 2
        while end < len(tokens) and depth:
            if tokens[end].text == "(":
                depth += 1
            if tokens[end].text == ")":
                depth -= 1
            end += 1
        if depth == 0:
            name_start = index
            while name_start >= 2 and tokens[name_start - 1].text in {".", "->"}:
                name_start -= 2
            name = canonical(tokens[name_start:index + 1])
            separator = tokens[index - 1].text if index >= 1 else ""
            indirect = separator in {".", "->"}
            member = token.text if indirect else None
            receiver = canonical(tokens[name_start:index - 1]) if indirect else None
            found.append(CallExpression(
                name,
                split_arguments(tokens[index + 2:end - 1]),
                tokens[name_start].start_byte,
                tokens[end - 1].end_byte,
                name_start,
                _call_result(tokens, name_start),
                receiver or None,
                member,
                None,
                indirect,
            ))
    enriched: list[CallExpression] = []
    for call in found:
        accessor_call = next((
            candidate
            for candidate in found
            if candidate is not call
            and candidate.end_byte == tokens[call.token_index].end_byte
        ), None)
        accessor = None if accessor_call is None else accessor_call.name
        receiver = call.receiver
        if accessor_call is not None:
            receiver = canonical(tokens[accessor_call.token_index:call.token_index + 1])
        enriched.append(CallExpression(
            call.name,
            call.arguments,
            call.start_byte,
            call.end_byte,
            call.token_index,
            call.result,
            receiver,
            call.member,
            accessor,
            call.is_indirect,
        ))
    return tuple(enriched)


def _statements(tokens: Sequence[Token]) -> tuple[tuple[Token, ...], ...]:
    statements: list[tuple[Token, ...]] = []
    start = 0
    for index, token in enumerate(tokens):
        if token.text == ";":
            statements.append(tuple(tokens[start:index]))
            start = index + 1
    return tuple(statements)


def _types(tokens: Sequence[Token]) -> dict[str, str]:
    found: dict[str, str] = {}
    aliases: dict[str, str] = {}
    for index, token in enumerate(tokens):
        if token.text != "typedef" or index + 1 >= len(tokens):
            continue
        kind_index = index + 1
        if tokens[kind_index].text not in {"struct", "union", "class"}:
            continue
        cursor = kind_index + 1
        tag = ""
        if cursor < len(tokens) and _IDENTIFIER.fullmatch(tokens[cursor].text):
            tag = tokens[cursor].text
            cursor += 1
        if cursor < len(tokens) and tokens[cursor].text == "{":
            depth = 1
            cursor += 1
            while cursor < len(tokens) and depth:
                depth += tokens[cursor].text == "{"
                depth -= tokens[cursor].text == "}"
                cursor += 1
        semicolon = next((
            position
            for position in range(cursor, len(tokens))
            if tokens[position].text == ";"
        ), None)
        if semicolon is None:
            continue
        alias = next((
            tokens[position].text
            for position in range(semicolon - 1, cursor - 1, -1)
            if _IDENTIFIER.fullmatch(tokens[position].text)
        ), None)
        if alias is not None:
            aliases[alias] = f"{tokens[kind_index].text} {tag or alias}"
    for index, token in enumerate(tokens[:-2]):
        if token.text not in {"struct", "union", "class"}:
            continue
        if _IDENTIFIER.fullmatch(tokens[index + 1].text) is None:
            continue
        object_index = index + 2
        while object_index < len(tokens) and tokens[object_index].text == "*":
            object_index += 1
        if (
            object_index < len(tokens)
            and _IDENTIFIER.fullmatch(tokens[object_index].text)
        ):
            found[tokens[object_index].text] = f"{token.text} {tokens[index + 1].text}"
    for index, token in enumerate(tokens[:-1]):
        resolved = aliases.get(token.text)
        if resolved is None:
            continue
        object_index = index + 1
        while object_index < len(tokens) and tokens[object_index].text == "*":
            object_index += 1
        if (
            object_index < len(tokens)
            and _IDENTIFIER.fullmatch(tokens[object_index].text)
            and tokens[object_index].text not in aliases
        ):
            found[tokens[object_index].text] = resolved
    return found


def _assignments(tokens: Sequence[Token]) -> tuple[AssignmentCandidate, ...]:
    found: list[AssignmentCandidate] = []
    for statement in _statements(tokens):
        equals = next((index for index, token in enumerate(statement)
                       if token.text == "="), None)
        if equals is None:
            continue
        left = _expression_tail(statement[:equals])
        right = tuple(statement[equals + 1:])
        if left and right and "{" not in (token.text for token in right):
            found.append(AssignmentCandidate(left, right, statement[equals].start_byte))
    return tuple(found)


def _member(tokens: Sequence[Token]) -> tuple[str, str] | None:
    if len(tokens) == 3 and tokens[1].text in {".", "->"}:
        return tokens[0].text, tokens[2].text
    return None


def _fields(tokens: Sequence[Token]) -> tuple[tuple[FieldCandidate, ...],
                                               tuple[FieldCandidate, ...]]:
    types = _types(tokens)
    stores: list[FieldCandidate] = []
    loads: list[FieldCandidate] = []
    for assignment in _assignments(tokens):
        left_member = _member(assignment.left)
        right_member = _member(assignment.right)
        if left_member is not None:
            receiver, field = left_member
            stores.append(FieldCandidate(types.get(receiver, ""), receiver, field,
                                         _expression_tail(assignment.right),
                                         assignment.order_byte))
        if right_member is not None:
            receiver, field = right_member
            loads.append(FieldCandidate(types.get(receiver, ""), receiver, field,
                                        assignment.left, assignment.order_byte))
    return tuple(stores), tuple(loads)


def _returns(tokens: Sequence[Token]) -> tuple[ReturnCandidate, ...]:
    found: list[ReturnCandidate] = []
    for statement in _statements(tokens):
        index = next((position for position, token in enumerate(statement)
                      if token.text == "return"), None)
        if index is not None and index + 1 < len(statement):
            value = _expression_tail(statement[index + 1:])
            found.append(ReturnCandidate(value, statement[index].start_byte))
    return tuple(found)


def _registrations(tokens: Sequence[Token]) -> tuple[RegistrationCandidate, ...]:
    types = _types(tokens)
    found: list[RegistrationCandidate] = []
    for index, token in enumerate(tokens[:-3]):
        if token.text != "." or tokens[index + 2].text != "=":
            continue
        brace = next((position for position in range(index - 1, -1, -1)
                      if tokens[position].text == "{"), None)
        if brace is None:
            continue
        equals = next((position for position in range(brace - 1, -1, -1)
                       if tokens[position].text == "="), None)
        if equals is None:
            continue
        receiver_tokens = _expression_tail(tokens[:equals])
        if not receiver_tokens:
            continue
        receiver = receiver_tokens[-1].text
        target_index = index + 3
        while (target_index < len(tokens)
               and _IDENTIFIER.fullmatch(tokens[target_index].text) is None):
            target_index += 1
        if target_index >= len(tokens):
            continue
        candidate_tokens = tuple(tokens[index:target_index + 1])
        found.append(RegistrationCandidate(types.get(receiver, ""), receiver,
                                           tokens[index + 1].text, tokens[target_index].text,
                                           candidate_tokens))
    return tuple(found)


def scan_source(source: str) -> ScannedSource:
    tokens = tokenize(source)
    body_start = next((token.start_byte for token in tokens if token.text == "{"), -1)
    calls = tuple(call for call in find_calls(tokens) if call.start_byte > body_start)
    field_stores, field_loads = _fields(tokens)
    assignments = _assignments(tokens)
    registrations = _registrations(tokens)
    unsupported_kinds: list[str] = []
    if "#" in (token.text for token in tokens):
        unsupported_kinds.append("preprocessor")
    if any(call.name in {"asm", "__asm__"} for call in calls):
        unsupported_kinds.append("inline_asm")
    if any(call.name.isupper() for call in calls):
        unsupported_kinds.append("uppercase_macro")
    if "({" in canonical(tokens):
        unsupported_kinds.append("gnu_statement_expression")
    identifiers = frozenset(
        token.text for token in tokens if _IDENTIFIER.fullmatch(token.text)
    )
    callbacks = {
        registration.target_name
        for registration in registrations
    }
    callbacks.update(
        assignment.right[0].text
        for assignment in assignments
        if len(assignment.right) == 1
        and _IDENTIFIER.fullmatch(assignment.right[0].text)
    )
    return ScannedSource(
        hashlib.sha256(source.encode("utf-8")).hexdigest(),
        tokens,
        calls,
        assignments,
        field_stores,
        field_loads,
        _returns(tokens),
        registrations,
        bool(unsupported_kinds),
        tuple(unsupported_kinds),
        identifiers,
        frozenset(callbacks),
    )
