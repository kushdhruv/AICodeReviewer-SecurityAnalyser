import operator
from typing import Annotated, Sequence, TypedDict

class DebateState(TypedDict):
    """
    The state object passed continuously through the LangGraph debate circle.
    """
    # Inputs from Phase 5
    original_code: str
    semgrep_finding: str
    rag_context: str
    joern_context: str  # Phase 4: Joern CPG taint flow context
    
    # Internal Debate State
    attacker_exploit: str # DeepSeek's theoretical attack plan
    defender_patch: str # DeepSeek's proposed secure code (MoA)
    judge_verdict: str # "PASS" or "FAIL"
    feedback: str # Reason for failure if the Judge rejects it
    
    # Built-in LangGraph safety net so it doesn't loop forever
    loop_count: int

