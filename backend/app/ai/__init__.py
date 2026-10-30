"""AI assistance layer: summarisation, insights, report narrative support and a grounded assistant.

Everything here is evidence-grounded: statements cite evidence and are checked by
reporting.verifier. An LLM is optional (see ai.llm); without one, deterministic generators
and retrieval are used.
"""
