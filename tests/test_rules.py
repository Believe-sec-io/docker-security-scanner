"""Tests of the rule catalog (identifiers, severities, coverage)."""

from __future__ import annotations

import pytest

from src.models import Category, SEVERITY_TAG, Severity
from src.rules import (
    RULES,
    RULES_BY_ID,
    RULE_IDS,
    get_rule,
    rules_by_category,
    unknown_rule_ids,
)


class TestCatalogStructure:
    def test_identifiers_are_unique_and_ordered(self) -> None:
        assert len(RULE_IDS) == len(set(RULE_IDS))
        assert list(RULE_IDS) == [rule.id for rule in RULES]

    @pytest.mark.parametrize("category", list(Category))
    def test_every_category_has_rules(self, category: Category) -> None:
        assert rules_by_category(category)

    def test_identifiers_follow_the_category_prefixes(self) -> None:
        prefixes = {
            Category.DOCKERFILE: "DF-",
            Category.COMPOSE: "CP-",
            Category.DAEMON: "DM-",
            Category.CONTAINER: "CT-",
        }
        for rule in RULES:
            assert rule.id.startswith(prefixes[rule.category]), rule.id

    def test_identifier_numbers_are_sequential_per_category(self) -> None:
        for category in Category:
            numbers = [int(rule.id.split("-")[1]) for rule in rules_by_category(category)]
            assert numbers == list(range(1, len(numbers) + 1)), category

    def test_no_rule_is_duplicated_in_the_lookup_table(self) -> None:
        assert len(RULES_BY_ID) == len(RULES)


class TestRuleMetadata:
    def test_every_rule_is_fully_documented(self) -> None:
        for rule in RULES:
            assert rule.title.strip(), rule.id
            assert rule.description.strip(), rule.id
            assert rule.remediation.strip(), rule.id
            assert rule.reference.strip(), rule.id

    def test_severities_use_the_shared_scale(self) -> None:
        for rule in RULES:
            assert isinstance(rule.severity, Severity)
            assert rule.severity in SEVERITY_TAG

    def test_no_rule_is_declared_as_info_only(self) -> None:
        """Every rule must have an actionable severity (INFO is never used)."""
        assert all(rule.severity is not Severity.INFO for rule in RULES)

    def test_critical_rules_exist_for_the_most_dangerous_cases(self) -> None:
        critical = {rule.id for rule in RULES if rule.severity is Severity.CRITICAL}
        assert {"DF-006", "CP-001", "CP-002", "CP-010", "DM-001", "CT-001", "CT-013"} <= critical

    def test_the_catalog_scales_from_critical_to_low(self) -> None:
        severities = {rule.severity for rule in RULES}
        assert Severity.CRITICAL in severities
        assert Severity.LOW in severities


class TestCatalogHelpers:
    def test_get_rule_returns_the_metadata(self) -> None:
        assert get_rule("DF-001").title == "Container runs as root"

    def test_get_rule_rejects_an_unknown_identifier(self) -> None:
        with pytest.raises(KeyError, match="unknown rule id"):
            get_rule("ZZ-999")

    def test_unknown_rule_ids_lists_only_the_missing_ones(self) -> None:
        assert unknown_rule_ids(["DF-001", "ZZ-001", "cp-002"]) == ["ZZ-001"]

    def test_unknown_rule_ids_is_empty_for_valid_input(self) -> None:
        assert unknown_rule_ids(list(RULE_IDS)) == []

    def test_catalog_covers_the_documented_families(self) -> None:
        counts = {category: len(rules_by_category(category)) for category in Category}
        assert counts[Category.DOCKERFILE] == 15
        assert counts[Category.COMPOSE] == 16
        assert counts[Category.DAEMON] == 13
        assert counts[Category.CONTAINER] == 17
        assert len(RULES) == 61