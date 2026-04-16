from langgraph.graph import StateGraph, START, END
from phases.phase6_agents.state import DebateState
from phases.phase6_agents.agents import AgentTeam
from utils.logger import get_logger

logger = get_logger(__name__)

def build_debate_graph():
    """
    Constructs the Adversarial State Machine.
    Attacker -> Defender -> Judge -> (if FAIL) -> Defender
                                  -> (if PASS) -> END
    """
    logger.info("Initializing AdvChain LangGraph Debate Engine...")
    team = AgentTeam()
    
    # 1. Initialize the Graph
    workflow = StateGraph(DebateState)
    
    # 2. Add the Agent Nodes
    workflow.add_node("attacker", team.attacker_node)
    workflow.add_node("defender", team.defender_node)
    workflow.add_node("judge", team.judge_node)
    
    # 3. Define the routing edges
    # Start -> Attacker
    workflow.add_edge(START, "attacker")
    
    # Attacker -> Defender
    workflow.add_edge("attacker", "defender")
    
    # Defender -> Judge
    workflow.add_edge("defender", "judge")
    
    # 4. Define the Conditional Logic (The Debate Loop)
    def judge_decision(state: DebateState):
        if state.get("judge_verdict") == "PASS":
            return END
        else:
            # If the judge says the patch failed, send it back to the defender
            logger.warning(f"[ROUTER] Patch rejected by Judge: {state.get('feedback')}. Retrying...")
            return "defender"
            
    workflow.add_conditional_edges(
        "judge",
        judge_decision
    )
    
    # Compile the graph
    app = workflow.compile()
    logger.info("LangGraph Debate Engine successfully compiled.")
    return app

# Module-level cached graph (built once, reused for all chunks)
_CACHED_DEBATE_APP = None

def run_debate(
    original_code: str,
    semgrep_finding: str,
    rag_context: str,
    joern_context: str = "No dataflow analysis available."
) -> dict:
    """
    Executes a single CodeChunk through the adversarial debate.
    MoA: Attacker (Qwen2.5) → Defender (DeepSeek-V2) → Judge (Qwen2.5)
    """
    global _CACHED_DEBATE_APP
    if _CACHED_DEBATE_APP is None:
        _CACHED_DEBATE_APP = build_debate_graph()
    app = _CACHED_DEBATE_APP
    
    # Initialize the starting state
    initial_state = {
        "original_code": original_code,
        "semgrep_finding": semgrep_finding,
        "rag_context": rag_context,
        "joern_context": joern_context,
        "loop_count": 0
    }
    
    logger.info("==== STARTING MoA DEBATE CYCLE ====")
    # The LangGraph app.invoke method automatically traverses the nodes based on our edges
    final_state = app.invoke(initial_state)
    logger.info("==== ENDING MoA DEBATE CYCLE ====")
    
    # Return the highly polished AdvChain patch and the Attacker's threat model
    return {
        "attacker_exploit": final_state.get("attacker_exploit"),
        "final_secure_patch": final_state.get("defender_patch"),
        "judge_verdict": final_state.get("judge_verdict", "UNKNOWN"),
    }
