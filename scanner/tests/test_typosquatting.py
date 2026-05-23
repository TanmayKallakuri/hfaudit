from __future__ import annotations


from hfaudit.triage.typosquatting import (
    TyposquatResult,
    _levenshtein,
    _normalize_homoglyphs,
    check_typosquatting,
)


class TestLevenshtein:
    def test_identical(self) -> None:
        assert _levenshtein("hello", "hello") == 0

    def test_empty_both(self) -> None:
        assert _levenshtein("", "") == 0

    def test_one_empty(self) -> None:
        assert _levenshtein("abc", "") == 3
        assert _levenshtein("", "xyz") == 3

    def test_single_substitution(self) -> None:
        assert _levenshtein("cat", "bat") == 1

    def test_single_insertion(self) -> None:
        assert _levenshtein("cat", "cats") == 1

    def test_single_deletion(self) -> None:
        assert _levenshtein("cats", "cat") == 1

    def test_multiple_edits(self) -> None:
        assert _levenshtein("kitten", "sitting") == 3

    def test_symmetric(self) -> None:
        assert _levenshtein("abc", "def") == _levenshtein("def", "abc")

    def test_unicode(self) -> None:
        assert _levenshtein("cafe", "café") == 1


class TestHomoglyphNormalization:
    def test_digit_zero_to_o(self) -> None:
        assert _normalize_homoglyphs("m0del") == "model"

    def test_digit_one_to_l(self) -> None:
        assert _normalize_homoglyphs("mode1") == "model"

    def test_rn_to_m(self) -> None:
        assert _normalize_homoglyphs("rnodel") == "model"

    def test_combined_homoglyphs(self) -> None:
        assert _normalize_homoglyphs("rn0de1") == "model"

    def test_no_change(self) -> None:
        assert _normalize_homoglyphs("clean") == "clean"


class TestCheckTyposquatting:
    def test_exact_match_not_suspicious(self) -> None:
        result = check_typosquatting("meta-llama/Llama-3.1-8B-Instruct")
        assert not result.is_suspicious
        assert result.edit_distance == 0
        assert result.similarity_score == 0.0

    def test_completely_different_name(self) -> None:
        result = check_typosquatting("totally-unique-org/my-custom-model-xyz")
        assert not result.is_suspicious

    def test_close_name_different_org_flagged(self) -> None:
        result = check_typosquatting("evil-org/Mistral-7B-v0.1")
        assert result.is_suspicious
        assert result.closest_match is not None
        assert "mistralai" in result.closest_match.lower() or "Mistral" in result.closest_match
        assert result.similarity_score >= 0.5

    def test_homoglyph_detected(self) -> None:
        result = check_typosquatting("evil-org/Llama-3.1-8B-1nstruct")
        assert result.is_suspicious
        assert result.similarity_score >= 0.5

    def test_suspicious_suffix_detected(self) -> None:
        result = check_typosquatting("shady/Mistral-7B-v0.1-uncensored")
        assert result.is_suspicious
        assert result.similarity_score >= 0.5

    def test_empty_input(self) -> None:
        result = check_typosquatting("")
        assert not result.is_suspicious
        assert result.closest_match is None

    def test_whitespace_input(self) -> None:
        result = check_typosquatting("   ")
        assert not result.is_suspicious

    def test_no_slash_model(self) -> None:
        result = check_typosquatting("bert-base-uncased")
        assert not result.is_suspicious
        assert result.edit_distance == 0

    def test_custom_corpus(self) -> None:
        corpus = frozenset({"acme/safe-model"})
        result = check_typosquatting("evil/safe-model", known_models=corpus)
        assert result.is_suspicious
        assert result.closest_match == "acme/safe-model"

    def test_custom_corpus_exact(self) -> None:
        corpus = frozenset({"acme/safe-model"})
        result = check_typosquatting("acme/safe-model", known_models=corpus)
        assert not result.is_suspicious

    def test_single_char_substitution_different_org(self) -> None:
        result = check_typosquatting("evil/whisper-large-v4")
        assert result.is_suspicious

    def test_result_has_correct_types(self) -> None:
        result = check_typosquatting("some-org/some-model")
        assert isinstance(result, TyposquatResult)
        assert isinstance(result.is_suspicious, bool)
        assert isinstance(result.similarity_score, float)
        assert 0.0 <= result.similarity_score <= 1.0
