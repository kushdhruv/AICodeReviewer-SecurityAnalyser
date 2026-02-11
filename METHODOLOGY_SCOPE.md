# Methodology Scope Clarification: Syntax, Semantic, and Security Analysis

Yes — this system should explicitly check **syntax issues** and **semantic issues**, in addition to security vulnerabilities.

## Recommended Layered Pipeline

1. **Syntax & Basic Correctness Layer (deterministic tools)**
   - Python parse/compile checks (`ast.parse`, `python -m py_compile`)
   - Linting for syntax/style breakage (e.g., Ruff/ESLint)
   - Type/interface checks (e.g., MyPy, TypeScript compiler)

2. **Semantic & Code-Quality Layer (static + light reasoning)**
   - Control/data-flow-informed checks from static analyzers
   - Complexity/dead-code/error-handling quality checks (Radon/Pylint-like signals)
   - Optional LLM reasoning for logic-level inconsistencies when static tools are inconclusive

3. **Security Pattern Layer (rule-based detection)**
   - Semgrep/Bandit/secret scanning for known vulnerability patterns
   - API/auth/config anti-pattern checks

4. **Security Reasoning Layer (LLM)**
   - Multi-function logic flaw detection (access-control bypass, business-logic abuse)
   - Contextual exploitability analysis
   - Prioritized remediation suggestions with secure code alternatives

5. **Unified Reporting Layer**
   - Consolidate findings under categories:
     - Syntax errors
     - Type/semantic defects
     - Security pattern findings
     - Logic-level security risks
   - Emit dashboard + PR comments + optional SARIF

## Why This Split Matters

- **Do not rely on LLM for syntax:** deterministic tools are faster and more accurate.
- **Use LLM where it adds value:** semantics and security reasoning across code context.
- **Lower false positives:** static findings become higher quality when validated by context-aware reasoning.
- **Better developer trust:** report source of each finding (tool vs model) and confidence.

## Output Contract (Suggested)

Each issue should include:
- `category`: `syntax | semantic | security-pattern | security-logic`
- `severity`: `low | medium | high | critical`
- `file`, `line_start`, `line_end`
- `evidence`: snippet or rule match
- `explanation`: human-readable impact
- `recommended_fix`: concrete remediation
- `source`: `deterministic_tool | static_analyzer | llm_reasoning`
- `confidence`: numeric or tiered score

This keeps your BTP scope complete while preserving strong engineering rigor.
