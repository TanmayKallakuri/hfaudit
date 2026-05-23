from __future__ import annotations

from dataclasses import dataclass

TOP_MODELS: frozenset[str] = frozenset({
    "meta-llama/Llama-3.1-8B-Instruct",
    "meta-llama/Llama-3.1-70B-Instruct",
    "meta-llama/Llama-3.1-405B-Instruct",
    "meta-llama/Llama-3-8B-Instruct",
    "meta-llama/Llama-3-70B-Instruct",
    "meta-llama/Llama-2-7b-chat-hf",
    "meta-llama/Llama-2-13b-chat-hf",
    "meta-llama/Llama-2-70b-chat-hf",
    "mistralai/Mistral-7B-v0.1",
    "mistralai/Mistral-7B-Instruct-v0.2",
    "mistralai/Mixtral-8x7B-Instruct-v0.1",
    "mistralai/Mistral-Nemo-Instruct-2407",
    "google/gemma-2-9b",
    "google/gemma-2-9b-it",
    "google/gemma-2-27b-it",
    "google/gemma-7b",
    "google/flan-t5-xxl",
    "google/flan-t5-large",
    "openai/whisper-large-v3",
    "openai/whisper-large-v2",
    "openai/whisper-medium",
    "openai/clip-vit-large-patch14",
    "openai/clip-vit-base-patch32",
    "stabilityai/stable-diffusion-xl-base-1.0",
    "stabilityai/stable-diffusion-2-1",
    "stabilityai/sdxl-turbo",
    "stabilityai/stablelm-zephyr-3b",
    "microsoft/phi-2",
    "microsoft/Phi-3-mini-4k-instruct",
    "microsoft/Phi-3-medium-4k-instruct",
    "Qwen/Qwen2-72B-Instruct",
    "Qwen/Qwen2-7B-Instruct",
    "Qwen/Qwen2-1.5B-Instruct",
    "tiiuae/falcon-40b-instruct",
    "tiiuae/falcon-7b-instruct",
    "bigscience/bloom",
    "bigscience/bloom-560m",
    "EleutherAI/gpt-neox-20b",
    "EleutherAI/pythia-12b",
    "EleutherAI/gpt-j-6b",
    "databricks/dolly-v2-12b",
    "HuggingFaceH4/zephyr-7b-beta",
    "NousResearch/Nous-Hermes-2-Mixtral-8x7B-DPO",
    "TheBloke/Llama-2-7B-Chat-GGUF",
    "bert-base-uncased",
    "bert-large-uncased",
    "distilbert-base-uncased",
    "roberta-base",
    "sentence-transformers/all-MiniLM-L6-v2",
    "sentence-transformers/all-mpnet-base-v2",
    "CompVis/stable-diffusion-v1-4",
    "runwayml/stable-diffusion-v1-5",
    "black-forest-labs/FLUX.1-dev",
})

_HOMOGLYPH_MAP: dict[str, str] = {
    "0": "o",
    "1": "l",
    "!": "l",
    "|": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "8": "b",
    "@": "a",
}

_SUSPICIOUS_SUFFIXES: tuple[str, ...] = (
    "-v2", "-v3", "-v4", "-v1", "-fixed", "-uncensored", "-unfiltered",
    "-leaked", "-latest", "-new", "-updated", "-patched", "-base",
    "-final", "-release", "-official", "-real",
)


@dataclass
class TyposquatResult:
    is_suspicious: bool
    closest_match: str | None
    edit_distance: int | None
    similarity_score: float
    reason: str


def _levenshtein(a: str, b: str) -> int:
    """Standard Levenshtein distance via full-matrix DP."""
    if len(a) < len(b):
        return _levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1] + [0] * len(b)
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            curr[j + 1] = min(curr[j] + 1, prev[j + 1] + 1, prev[j] + cost)
        prev = curr
    return prev[len(b)]


def _normalize_homoglyphs(text: str) -> str:
    """Replace common homoglyph characters with their canonical forms."""
    out: list[str] = []
    for ch in text:
        out.append(_HOMOGLYPH_MAP.get(ch, ch))
    result = "".join(out)
    result = result.replace("rn", "m")
    result = result.replace("vv", "w")
    return result


def _split_model_id(model_id: str) -> tuple[str | None, str]:
    """Split 'org/name' into (org, name). If no slash, returns (None, model_id)."""
    if "/" in model_id:
        parts = model_id.split("/", 1)
        return parts[0], parts[1]
    return None, model_id


def _strip_suspicious_suffix(name: str) -> tuple[str, str | None]:
    """Strip known suspicious suffixes, return (base, suffix_found)."""
    lower = name.lower()
    for suffix in _SUSPICIOUS_SUFFIXES:
        if lower.endswith(suffix):
            return name[: len(name) - len(suffix)], suffix
    return name, None


def check_typosquatting(
    model_id: str, known_models: frozenset[str] | None = None
) -> TyposquatResult:
    """Check whether a model identifier looks like it's impersonating a known model."""
    if not model_id or not model_id.strip():
        return TyposquatResult(
            is_suspicious=False,
            closest_match=None,
            edit_distance=None,
            similarity_score=0.0,
            reason="Empty model identifier",
        )

    corpus = known_models if known_models is not None else TOP_MODELS

    if model_id in corpus:
        return TyposquatResult(
            is_suspicious=False,
            closest_match=model_id,
            edit_distance=0,
            similarity_score=0.0,
            reason="Exact match to known model",
        )

    input_org, input_name = _split_model_id(model_id)
    input_name_lower = input_name.lower()
    input_name_normalized = _normalize_homoglyphs(input_name_lower)

    best_dist: int | None = None
    best_match: str | None = None
    best_score: float = 0.0
    best_reason: str = ""

    for known in corpus:
        known_org, known_name = _split_model_id(known)
        known_name_lower = known_name.lower()
        known_name_normalized = _normalize_homoglyphs(known_name_lower)

        same_org = (
            input_org is not None
            and known_org is not None
            and input_org.lower() == known_org.lower()
        )

        dist_raw = _levenshtein(input_name_lower, known_name_lower)
        dist_normalized = _levenshtein(input_name_normalized, known_name_normalized)
        dist = min(dist_raw, dist_normalized)

        max_len = max(len(input_name), len(known_name), 1)
        raw_similarity = 1.0 - (dist / max_len)

        homoglyph_detected = dist_normalized < dist_raw

        stripped_name, suffix_found = _strip_suspicious_suffix(input_name)
        dist_after_strip: int | None = None
        if suffix_found is not None:
            stripped_lower = stripped_name.lower()
            stripped_normalized = _normalize_homoglyphs(stripped_lower)
            dist_after_strip = min(
                _levenshtein(stripped_lower, known_name_lower),
                _levenshtein(stripped_normalized, known_name_normalized),
            )

        score = 0.0
        reason_parts: list[str] = []

        is_different_org = not same_org and input_org is not None and known_org is not None

        if dist <= 2 and is_different_org:
            score = max(score, 0.85 + (0.15 * raw_similarity))
            reason_parts.append(
                f"edit distance {dist} from '{known}' with different org"
            )

        if dist <= 2 and (input_org is None or known_org is None):
            score = max(score, 0.7 + (0.15 * raw_similarity))
            reason_parts.append(
                f"edit distance {dist} from '{known}' (org mismatch or missing)"
            )

        if homoglyph_detected and dist_normalized <= 2 and is_different_org:
            score = max(score, 0.9)
            reason_parts.append(
                f"homoglyph substitution detected near '{known}'"
            )

        if dist_after_strip is not None and dist_after_strip <= 1 and is_different_org:
            score = max(score, 0.8)
            reason_parts.append(
                f"suspicious suffix '{suffix_found}' on name close to '{known}'"
            )

        if dist <= 4 and known_name_lower in input_name_lower and is_different_org:
            score = max(score, 0.6)
            reason_parts.append(
                f"known model name '{known_name}' is substring with distance {dist}"
            )

        if score > best_score or (score == best_score and dist < (best_dist or 999)):
            best_score = score
            best_dist = dist
            best_match = known
            best_reason = "; ".join(reason_parts) if reason_parts else ""

    is_suspicious = best_score >= 0.5

    if not best_reason and best_match is not None:
        best_reason = f"Closest known model: '{best_match}' (distance {best_dist})"

    return TyposquatResult(
        is_suspicious=is_suspicious,
        closest_match=best_match,
        edit_distance=best_dist,
        similarity_score=round(best_score, 4),
        reason=best_reason if best_reason else "No close match found",
    )
