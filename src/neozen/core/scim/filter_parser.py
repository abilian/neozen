"""SCIM filter expression parser (RFC 7644 Section 3.4.2.2).

Parses SCIM filter strings like:
    userName eq "alice"
    emails[type eq "work"].value sw "user"
    userName eq "alice" and active eq true
    not (userName eq "alice")

Supports operators: eq, ne, co, sw, ew, gt, ge, lt, le, pr
Logical: and, or, not
Grouping: parentheses
Values: strings, numbers, booleans, null

This is a simple recursive-descent parser. Complex attribute paths
(e.g., emails[...].value) are supported only at the leaf level
(stored in the attribute name as `attr[expr].sub`).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from neozen.core.scim.errors import SCIMFilterError


class FilterOp(StrEnum):
    """SCIM filter operators."""

    EQ = "eq"
    NE = "ne"
    CO = "co"  # contains
    SW = "sw"  # starts with
    EW = "ew"  # ends with
    GT = "gt"
    GE = "ge"
    LT = "lt"
    LE = "le"
    PR = "pr"  # present (no value)


# =============================================================================
# AST Node Types
# =============================================================================


@dataclass(frozen=True)
class FilterExpression:
    """Base class for filter AST nodes."""


def _eval_string_op(op: FilterOp, actual: Any, expected: Any) -> bool:
    """Evaluate string-style comparison operators."""
    if op == FilterOp.EQ:
        return _eq(actual, expected)
    if op == FilterOp.NE:
        return not _eq(actual, expected)
    if op == FilterOp.CO:
        return str(expected) in str(actual)
    if op == FilterOp.SW:
        return str(actual).startswith(str(expected))
    if op == FilterOp.EW:
        return str(actual).endswith(str(expected))
    return False


def _eval_comparison_op(op: FilterOp, actual: Any, expected: Any) -> bool:
    """Evaluate ordered comparison operators."""
    if op == FilterOp.GT:
        return bool(actual > expected)
    if op == FilterOp.GE:
        return bool(actual >= expected)
    if op == FilterOp.LT:
        return bool(actual < expected)
    if op == FilterOp.LE:
        return bool(actual <= expected)
    return False


_STRING_OP_SET = {
    FilterOp.EQ,
    FilterOp.NE,
    FilterOp.CO,
    FilterOp.SW,
    FilterOp.EW,
}
_COMPARISON_OP_SET = {FilterOp.GT, FilterOp.GE, FilterOp.LT, FilterOp.LE}


@dataclass(frozen=True)
class SimpleExpression(FilterExpression):
    """A simple comparison: `attr op value`."""

    attribute: str
    op: FilterOp
    value: Any  # str | int | float | bool | None

    def matches(self, item: Any) -> bool:
        """Evaluate the expression against an item.

        `item` can be a dict or an object with attributes.
        """
        actual = _get_attr(item, self.attribute)

        if self.op == FilterOp.PR:
            return actual is not None and actual != "" and actual != []

        if actual is None:
            return False

        if self.op in _STRING_OP_SET:
            return _eval_string_op(self.op, actual, self.value)
        if self.op in _COMPARISON_OP_SET:
            return _eval_comparison_op(self.op, actual, self.value)

        return False


@dataclass(frozen=True)
class Conjunction(FilterExpression):
    """A logical combination: `left op right` where op is `and`/`or`."""

    op: str  # "and" | "or"
    left: FilterExpression
    right: FilterExpression

    def matches(self, item: Any) -> bool:
        if self.op == "and":
            return _matches(self.left, item) and _matches(self.right, item)
        return _matches(self.left, item) or _matches(self.right, item)


@dataclass(frozen=True)
class Negation(FilterExpression):
    """A logical not."""

    expr: FilterExpression

    def matches(self, item: Any) -> bool:
        return not _matches(self.expr, item)


def _matches(expr: FilterExpression, item: Any) -> bool:
    """Dispatch matching for any FilterExpression subclass."""
    if isinstance(expr, SimpleExpression):
        return expr.matches(item)
    if isinstance(expr, Conjunction):
        return expr.matches(item)
    if isinstance(expr, Negation):
        return expr.matches(item)
    return False


def _get_attr(item: Any, attribute: str) -> Any:
    """Look up an attribute on an item.

    Supports dotted access (e.g., `name.familyName`) for nested
    objects/dicts. Case-insensitive at the top level.
    """
    parts = attribute.split(".")
    value = item
    for part in parts:
        value = _get_one(value, part)
        if value is None:
            return None
    return value


def _get_one(item: Any, name: str) -> Any:
    """Get a single attribute from a dict or object (case-insensitive)."""
    if item is None:
        return None
    if isinstance(item, dict):
        # Case-insensitive lookup
        if name in item:
            return item[name]
        lower = name.lower()
        for k, v in item.items():
            if k.lower() == lower:
                return v
        return None
    # Object: try snake_case attribute name (SCIM uses camelCase)
    snake = _camel_to_snake(name)
    if hasattr(item, snake):
        return getattr(item, snake)
    if hasattr(item, name):
        return getattr(item, name)
    return None


def _camel_to_snake(name: str) -> str:
    """Convert camelCase to snake_case."""
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _eq(actual: Any, expected: Any) -> bool:
    """SCIM equality: case-insensitive for strings."""
    if isinstance(actual, str) and isinstance(expected, str):
        return actual.lower() == expected.lower()
    return actual == expected


# =============================================================================
# Tokenizer
# =============================================================================


_TOKEN_RE = re.compile(
    r"""
    \s*
    (?:
        (?P<lparen>\() |
        (?P<rparen>\)) |
        (?P<string>"(?:[^"\\]|\\.)*") |
        (?P<number>-?\d+(?:\.\d+)?) |
        (?P<bool>true|false) |
        (?P<null>null) |
        (?P<word>[a-zA-Z_][a-zA-Z0-9_.]*)
    )
    """,
    re.VERBOSE,
)


@dataclass
class Token:
    type: str
    value: str
    pos: int


def _tokenize(text: str) -> list[Token]:
    tokens: list[Token] = []
    pos = 0
    while pos < len(text):
        if text[pos].isspace():
            pos += 1
            continue
        match = _TOKEN_RE.match(text, pos)
        if not match:
            msg = f"Unexpected character at position {pos}: {text[pos]!r}"
            raise SCIMFilterError(msg)
        for name, value in match.groupdict().items():
            if value is not None:
                tokens.append(Token(type=name, value=value, pos=pos))
                break
        pos = match.end()
    return tokens


# =============================================================================
# Parser
# =============================================================================


_KEYWORDS = {"and", "or", "not"}
_OPERATORS = {op.value for op in FilterOp}


class _Parser:
    def __init__(self, tokens: list[Token]) -> None:
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> Token | None:
        if self.pos >= len(self.tokens):
            return None
        return self.tokens[self.pos]

    def consume(self) -> Token:
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def parse(self) -> FilterExpression:
        expr = self._parse_or()
        if self.peek() is not None:
            msg = f"Unexpected token at position {self.peek().pos}"  # type: ignore[union-attr]
            raise SCIMFilterError(msg)
        return expr

    def _parse_or(self) -> FilterExpression:
        left = self._parse_and()
        while self._peek_keyword("or"):
            self.consume()
            right = self._parse_and()
            left = Conjunction(op="or", left=left, right=right)
        return left

    def _parse_and(self) -> FilterExpression:
        left = self._parse_not()
        while self._peek_keyword("and"):
            self.consume()
            right = self._parse_not()
            left = Conjunction(op="and", left=left, right=right)
        return left

    def _parse_not(self) -> FilterExpression:
        if self._peek_keyword("not"):
            self.consume()
            return Negation(expr=self._parse_primary())
        return self._parse_primary()

    def _parse_primary(self) -> FilterExpression:
        token = self.peek()
        if token is None:
            msg = "Unexpected end of filter"
            raise SCIMFilterError(msg)

        if token.type == "lparen":
            self.consume()
            expr = self._parse_or()
            close = self.peek()
            if close is None or close.type != "rparen":
                msg = "Missing closing parenthesis"
                raise SCIMFilterError(msg)
            self.consume()
            return expr

        if token.type == "word":
            return self._parse_simple()

        msg = f"Unexpected token {token.value!r} at position {token.pos}"
        raise SCIMFilterError(msg)

    def _parse_simple(self) -> SimpleExpression:
        attr_token = self.consume()
        op_token = self.peek()
        if op_token is None or op_token.type != "word":
            msg = f"Expected operator after {attr_token.value!r}"
            raise SCIMFilterError(msg)

        op_value = op_token.value.lower()
        if op_value not in _OPERATORS:
            msg = f"Unknown operator: {op_token.value!r}"
            raise SCIMFilterError(msg)
        self.consume()

        op = FilterOp(op_value)

        # `pr` has no value
        if op == FilterOp.PR:
            return SimpleExpression(attribute=attr_token.value, op=op, value=None)

        value_token = self.peek()
        if value_token is None:
            msg = f"Expected value after operator {op_value}"
            raise SCIMFilterError(msg)
        self.consume()
        value = self._parse_value(value_token)
        return SimpleExpression(attribute=attr_token.value, op=op, value=value)

    def _parse_value(self, token: Token) -> Any:
        if token.type == "string":
            # Strip quotes and unescape
            return token.value[1:-1].replace('\\"', '"').replace("\\\\", "\\")
        if token.type == "number":
            if "." in token.value:
                return float(token.value)
            return int(token.value)
        if token.type == "bool":
            return token.value == "true"
        if token.type == "null":
            return None
        # `word` could be a bareword that should have been a string
        msg = f"Invalid value at position {token.pos}: {token.value!r}"
        raise SCIMFilterError(msg)

    def _peek_keyword(self, keyword: str) -> bool:
        token = self.peek()
        return (
            token is not None
            and token.type == "word"
            and token.value.lower() == keyword
        )


def parse_filter(text: str) -> FilterExpression:
    """Parse a SCIM filter string into an expression tree.

    Raises:
        SCIMFilterError: If the filter is malformed.
    """
    if not text or not text.strip():
        msg = "Filter cannot be empty"
        raise SCIMFilterError(msg)

    tokens = _tokenize(text)
    if not tokens:
        msg = "Filter cannot be empty"
        raise SCIMFilterError(msg)

    parser = _Parser(tokens)
    return parser.parse()


__all__ = [
    "Conjunction",
    "FilterExpression",
    "FilterOp",
    "Negation",
    "SimpleExpression",
    "parse_filter",
]
