# Agentic-AI-Code-Review-System
This repository implements a multi‑stage, agentic pipeline for automated security and quality analysis of Python codebases. It combines several specialized “agents” to deliver comprehensive, precise, and context‑aware findings:

AST Security Analyzer

Parses each Python file into an Abstract Syntax Tree

Detects dangerous calls (eval, exec, pickle.loads, os.system, etc.) with CWE mappings

Tracks user‑input taint sources (e.g. input(), request.args) and propagates taint through assignments and function returns

Flags SQL‑injection patterns (%‑formatting, string concatenation) and shell injections

Bandit Integration

Runs the industry‑standard Bandit scanner to catch hundreds of common security issues

Merges Bandit findings with AST results, boosting confidence of overlapping issues

Taint‑Tracking Agent

Records where untrusted data enters the program and how it reaches dangerous sinks

Only flags sinks (e.g. command execution, file writes) when they see truly tainted variables

Gemini Semantic Agent

Leverages Google’s Gemini LLM to perform high‑level, context‑aware reasoning

Receives existing AST/Bandit issues as prompts to avoid duplication

Identifies business logic flaws, race conditions, authorization bypasses, and other deep semantic defects

Orchestration & Cross‑Validation

Groups and fuzzily matches issues from different agents

Boosts confidence when multiple agents agree, and highlights unique findings

Rate‑limits LLM calls to respect API quotas and handles malformed JSON gracefully

Key Features

Modular Architecture: Each stage is encapsulated in its own class or function, making it easy to extend or replace individual agents.

Rich Metadata: Every CodeIssue carries file path, line number, source, severity, CWE ID, context, and taint provenance.

CLI‑Driven: Invoke via command line with python enhanced_review.py /path/to/repo --gemini_api_key YOUR_KEY.

Configurable & Extensible: Add new taint sources, sanitizers, or dangerous‑function rules in the AST analyzer.

High Precision: Combines AST, static analysis (Bandit), data‑flow tracking, and LLM reasoning to minimize false positives.
