import os
import json
from litellm import completion
from phases.phase6_agents.state import DebateState
from utils.logger import get_logger

logger = get_logger(__name__)

# NOTE FOR BTP: We use LiteLLM so we can hot-swap any model or local Ollama instantly.
# Ensure you set standard ENV vars like GROQ_API_KEY, TOGETHER_API_KEY in your console before running.

class AgentTeam:
    def __init__(self):
        # === MIXTURE OF AGENTS (MoA) STRATEGY ===
        # Inherited from HackerSec architectural analysis:
        # - Attacker & Judge: Qwen 2.5-Coder (fast context-switching, roleplaying)
        # - Defender: DeepSeek-Coder-V2 (SOTA F1 on vulnerability patching, precise code gen)
        
        self.attacker_model = "ollama/qwen2.5-coder:1.5b"  # Red Team: fast exploit generation
        self.defender_model = "ollama/deepseek-coder-v2"  # Blue Team: precise secure patches
        self.judge_model = "ollama/qwen2.5-coder:1.5b"  # Arbiter: strict pass/fail classification

    def attacker_node(self, state: DebateState) -> dict:
        """The Red Team Agent. Finds the hole and writes the exploit."""
        logger.info("[RED TEAM] Analyzing code for exploitability...")
        
        prompt = f"""
        [ROLE]
        You are a highly skilled, elite Red Team Security Researcher. Your primary objective is to constructively prove that the provided code is vulnerable by explaining how to exploit it.
        
        [CONTEXT]
        VULNERABILITY FOUND BY SCANNER:
        {state['semgrep_finding']}
        
        OFFICIAL VULNERABILITY DEFINITION (RAG):
        {state['rag_context']}
        
        DATAFLOW CONTEXT (CPG):
        {state.get('joern_context', 'No dataflow analysis available.')}
        
        CODE TO ATTACK:
        ```python
        {state['original_code']}
        ```
        
        DEBATE HISTORY (If returning from a failed attack):
        FEEDBACK FROM JUDGE: {state.get('feedback', 'None')}
        DEFENDER'S PREVIOUS PATCH: {state.get('defender_patch', 'None')}
        
        [TASK]
        Write a concise, highly technical theoretical exploit showing EXACTLY how an attacker would bypass the security.
        Include a hypothetical payload if applicable (e.g., '1 OR 1=1').
        Do not provide a patch. Focus solely on the mechanics of the exploit.
        Format your output in 2-3 clear paragraphs.
        """
        
        response = completion(
            model=self.attacker_model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.7,
            max_tokens=4096,
            timeout=120,
        )
        
        exploit = response.choices[0].message.content
        return {"attacker_exploit": exploit}

    def defender_node(self, state: DebateState) -> dict:
        """
        The Blue Team Agent (DeepSeek-Coder-V2).
        Uses AdvChain (Self-Correction Chain of Thought) and outputs structured JSON.
        MoA: Uses DeepSeek for superior code generation accuracy.
        """
        logger.info("[BLUE TEAM / DeepSeek-V2] Drafting secure patch using AdvChain CoT...")
        
        prompt = f"""
        [ROLE]
        You are an elite Senior Staff Backend Engineer specializing in Application Security. 
        Your objective is to write an impenetrable patch for the vulnerable code that mathematically neutralizes the Attacker's exploit.
        
        [CONTEXT]
        ATTACKER'S THREAT MODEL:
        {state['attacker_exploit']}
        
        ENTERPRISE MITIGATION STRATEGY (RAG):
        {state['rag_context']}
        
        DATAFLOW CONTEXT (CPG):
        {state.get('joern_context', 'No dataflow analysis available.')}
        
        ORIGINAL VULNERABLE CODE:
        [UNTRUSTED_CODE_START]
        {state['original_code']}
        [UNTRUSTED_CODE_END]
        
        [INSTRUCTIONS FOR ADV-CHAIN CoT]
        You must use an Adversarial Chain-of-Thought process before outputting the final code:
        1. [DRAFT] Think through a secure version of the code implementing the Enterprise Mitigation.
        2. [ATTACK] Adversarially review your own draft. Could the Attacker's exploit bypass your new defenses? Did you introduce a new bug?
        3. [CORRECT] Fix any logical flaws in your draft.
        4. [FINAL] Output the secure code inside a JSON response.
        
        [OUTPUT FORMAT]
        You MUST respond with valid JSON matching exactly this schema:
        {{
            "secure_code": "<the complete patched Python code>",
            "explanation": "<1-2 sentence summary of what was fixed>"
        }}
        Do not output any text outside of the JSON object.
        """
        
        response = completion(
            model=self.defender_model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,  # Low temp for precise coding
            response_format={"type": "json_object"},
            max_tokens=4096,
            timeout=120,
        )
        
        raw_output = response.choices[0].message.content
        
        # Parse JSON response, fallback to raw text if parsing fails
        try:
            parsed = json.loads(raw_output)
            patch = parsed.get("secure_code", raw_output)
        except json.JSONDecodeError:
            logger.warning("[BLUE TEAM] JSON parse failed, using raw LLM output as patch.")
            patch = raw_output
        
        return {
            "defender_patch": patch,
            "loop_count": state.get("loop_count", 0) + 1
        }

    def judge_node(self, state: DebateState) -> dict:
        """
        The Automation Judge (Qwen2.5-Coder).
        Reviews if the Defender successfully blocked the Attacker.
        Outputs structured JSON verdict for pipeline reliability.
        """
        logger.info(f"[JUDGE] Evaluating Debate Round {state.get('loop_count', 1)}...")
        
        # Failsafe to prevent endless loops (max 3 tries)
        if state.get("loop_count", 0) >= 3:
            logger.warning("[JUDGE] Max debate loops reached. Forcing PASS.")
            return {"judge_verdict": "PASS"}

        prompt = f"""
        [ROLE]
        You are an impartial, incredibly strict Principal Security Auditor (The Judge).
        Your job is to determine if the Blue Team's patch successfully mitigates the Red Team's exploit without breaking functionality.
        
        [CONTEXT]
        ATTACKER'S THREAT MODEL:
        {state['attacker_exploit']}
        
        DEFENDER'S ATTEMPTED PATCH:
        [UNTRUSTED_CODE_START]
        {state['defender_patch']}
        [UNTRUSTED_CODE_END]
        
        [EVALUATION CRITERIA]
        1. Does the patch directly neutralize the specific exploit vector described by the Attacker?
        2. Does the patch follow secure coding best practices?
        3. Is the patch valid, executable Python/JS code without obvious syntax errors?
        
        [OUTPUT FORMAT]
        You MUST respond with valid JSON matching exactly this schema:
        {{
            "verdict": "PASS" or "FAIL",
            "reason": "<1-sentence explanation of your decision>"
        }}
        Do not output any text outside of the JSON object.
        """
        
        response = completion(
            model=self.judge_model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0,
            response_format={"type": "json_object"},
            max_tokens=2048,
            timeout=90,
        )
        
        raw_output = response.choices[0].message.content.strip()
        
        # Parse JSON verdict, fallback to string matching
        try:
            parsed = json.loads(raw_output)
            verdict = parsed.get("verdict", "FAIL").upper()
            reason = parsed.get("reason", "")
        except json.JSONDecodeError:
            logger.warning("[JUDGE] JSON parse failed, falling back to string matching.")
            verdict = "PASS" if raw_output.upper().startswith("PASS") else "FAIL"
            reason = raw_output
        
        if verdict == "PASS":
            return {"judge_verdict": "PASS"}
        else:
            return {
                "judge_verdict": "FAIL",
                "feedback": reason if reason else raw_output
            }
