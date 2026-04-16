"""
AI Security Code Reviewer — Master Pipeline (v2.0)
Architecture: FastAPI + Celery + LangGraph MoA + ML Fusion Classifier

Pipeline Flow:
  Phase 1: Repository Ingestion (Git/ZIP)
  Phase 2: AST Parsing (tree-sitter) 
  Phase 3: Static Analysis (Semgrep + Ruff)
  Phase 4: Dataflow Analysis (Joern CPG) [graceful skip if unavailable]
  Phase 4.5: ML Fusion Classifier (false positive filtering)
  Phase 5: RAG Knowledge Base (ChromaDB + BGE-Small)
  Phase 6: LangGraph Adversarial Debate (MoA: Qwen2.5 + DeepSeek-V2)
  Phase 7: Patch Application (file overwrite with backup)
  Phase 10: Report Generation (JSON + HTML)
"""

import asyncio
import json
from typing import List
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from phases.phase1_ingestion.loader import RepoLoader
from phases.phase2_parsing.parser import CodeParser, CodeChunk
from phases.phase3_scanning.scanner import StaticScanner
from phases.phase4_dataflow.joern_runner import JoernRunner
from phases.phase7_patching.apply import PatchApplicator
from phases.phase10_reporting.generator import (
    ReportGenerator, PipelineReport, VulnerabilityReport
)
from utils.logger import get_logger
from dotenv import load_dotenv
import os

# Disable ChromaDB Telemetry completely
os.environ["ANONYMIZED_TELEMETRY"] = "False"
os.environ["CHROMA_SERVER_TELEMETRY"] = "False"

load_dotenv()  # Load API keys from .env automatically

logger = get_logger(__name__)

# ============================================================
# FastAPI Application
# ============================================================
app = FastAPI(
    title="AI Security Code Reviewer",
    description="Multi-phase AI pipeline for detecting and patching vulnerabilities",
    version="2.0.0",
)

# Mount static files for frontend UI
import os
os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Mount reports directory so frontend can fetch JSON
os.makedirs("reports", exist_ok=True)
app.mount("/reports", StaticFiles(directory="reports"), name="reports")

@app.get("/")
async def serve_frontend():
    """Serves the main frontend UI."""
    return FileResponse("static/index.html")


class AnalyzeRequest(BaseModel):
    """Request body for the /analyze endpoint."""
    repo_url: str
    auto_patch: bool = False  # If True, auto-apply approved patches


class AnalyzeResponse(BaseModel):
    """Response body for the /analyze endpoint."""
    status: str
    total_files_scanned: int
    total_findings: int
    findings_after_ml_filter: int
    vulnerabilities_confirmed: int
    patches_applied: int
    report_path: str


# ============================================================
# Core Pipeline (can be called via API or CLI)
# ============================================================
async def run_pipeline(
    target_repo: str,
    auto_patch: bool = False,
    workspace_path: str = "./workspace"
) -> dict:
    """
    Executes the full security analysis pipeline end-to-end.
    """
    logger.info("🚀 Starting AI Security Code Reviewer Pipeline v2.0 (MoA Architecture)")

    report = PipelineReport(target_repository=target_repo)
    report_gen = ReportGenerator()

    # --- PHASE 1: INGESTION ---
    logger.info("═" * 60)
    logger.info("[Phase 1] Repository Ingestion")
    loader = RepoLoader(workspace_path=workspace_path)

    try:
        logger.info(f"Downloading/Extracting: {target_repo}...")
        code_files = await loader.load(target_repo)
        report.total_files_scanned = len(code_files)
        logger.info(f"✅ Extracted {len(code_files)} valid code files.")
    except Exception as e:
        logger.error(f"❌ Failed to load repository: {e}")
        raise

    # --- PHASE 2: PARSING (Multi-Language) ---
    logger.info("═" * 60)
    logger.info("[Phase 2] AST Parsing (tree-sitter — Multi-Language)")
    parser = CodeParser()

    all_chunks: List[CodeChunk] = []
    supported_exts = parser.get_supported_extensions()
    parseable_files = [f for f in code_files if f.suffix.lower() in supported_exts]
    logger.info(f"Found {len(parseable_files)} parseable files ({len(code_files)} total discovered).")

    for file in parseable_files:
        chunks = parser.parse_file(file)
        if chunks:
            all_chunks.extend(chunks)
            logger.info(f"  Parsed {len(chunks)} blocks from {file.name} ({chunks[0].language})")

    report.total_code_blocks = len(all_chunks)
    logger.info(f"✅ Total code blocks extracted: {len(all_chunks)}")

    # --- PHASE 3: STATIC SCANNING (Ruff + Semgrep + Secrets) ---
    logger.info("═" * 60)
    logger.info("[Phase 3] Static Analysis (Ruff + Semgrep + Secret Scanner)")
    scanner = StaticScanner(workspace_path=workspace_path)

    raw_findings = await scanner.run_scans()
    vulnerable_chunks = scanner.correlate_findings(all_chunks, raw_findings)
    report.total_static_findings = len(raw_findings)

    # Secret scanning (regex + entropy-based)
    from phases.phase3_scanning.secret_scanner import SecretScanner
    secret_scanner = SecretScanner()
    repo_dirs_for_secrets = list(Path(workspace_path).glob("repo_*"))
    secret_findings = []
    if repo_dirs_for_secrets:
        secret_findings = secret_scanner.scan_directory(repo_dirs_for_secrets[0])
        for sf in secret_findings:
            logger.warning(f"  🔑 SECRET: {sf.secret_type} in {Path(sf.file_path).name}:{sf.line_number}")
    logger.info(f"Secret Scanner: {len(secret_findings)} potential secrets found.")

    # --- PHASE 9: DEPENDENCY SCANNING (SCA) ---
    logger.info("═" * 60)
    logger.info("[Phase 9] Dependency Vulnerability Scanning (pip-audit)")
    from phases.phase9_dependency.scanner import DependencyScanner
    dep_scanner = DependencyScanner(workspace_path=workspace_path)
    dep_result = await dep_scanner.scan()
    if dep_result.findings:
        for df in dep_result.findings:
            logger.warning(f"  📦 VULN DEP: {df.package_name}=={df.installed_version} ({df.vulnerability_id})")
    logger.info(dep_scanner.format_for_report(dep_result))

    # --- PHASE 4: DATAFLOW ANALYSIS (JOERN CPG — Server-Based) ---
    logger.info("═" * 60)
    logger.info("[Phase 4] Dataflow & Taint Analysis (Joern CPG Server)")
    joern = JoernRunner()

    # Initialize CPG once — per-finding queries happen later in Phase 6
    repo_dirs = list(Path(workspace_path).glob("repo_*"))
    joern_available = False

    if repo_dirs:
        joern_available = joern.initialize_cpg(repo_dirs[0])
        if joern_available:
            logger.info("✅ Joern CPG ready. Per-finding queries will run in Phase 6.")
        else:
            logger.info("⚠️ Joern unavailable. Pipeline continues without dataflow analysis.")

    # --- PHASE 4.5: ML FUSION CLASSIFIER ---
    logger.info("═" * 60)
    logger.info("[Phase 4.5] ML Fusion Classifier (False Positive Reduction)")
    from phases.phase_ml_fusion.classifier import FusionClassifier

    ml_classifier = FusionClassifier()
    ml_predictions = {}  # chunk_name -> {prediction, confidence}

    if vulnerable_chunks:
        filtered_chunks = []
        for chunk in vulnerable_chunks:
            result = ml_classifier.predict_chunk(chunk)
            ml_predictions[chunk.chunk.name] = result
            if result["prediction"] == "true_positive":
                filtered_chunks.append(chunk)
                logger.info(f"  ✅ KEEP: {chunk.chunk.name} (confidence={result['confidence']})")
            else:
                logger.info(f"  🗑️ DROP: {chunk.chunk.name} (confidence={result['confidence']})")

        report.findings_after_ml_filter = len(filtered_chunks)
        logger.info(
            f"ML Filter: {len(vulnerable_chunks)} → {len(filtered_chunks)} "
            f"({len(vulnerable_chunks) - len(filtered_chunks)} false positives dropped)"
        )
    else:
        filtered_chunks = []
        report.findings_after_ml_filter = 0

    # --- PHASE 5: RAG VULNERABILITY DATABASE ---
    logger.info("═" * 60)
    logger.info("[Phase 5] RAG Knowledge Base (ChromaDB + BGE-Small)")
    from phases.phase5_rag.vector_store import get_rag_database

    db = get_rag_database()

    if filtered_chunks:
        final_chunks = db.enhance_chunks(filtered_chunks)
    else:
        final_chunks = []

    logger.info(f"✅ {len(final_chunks)} contextualized chunks queued for Phase 6 MoA Debate.")

    # --- PHASE 6: MULTI-AGENT ORCHESTRATION (MoA) ---
    if final_chunks:
        logger.info("═" * 60)
        logger.info("[Phase 6] LangGraph Adversarial Debate (MoA: Qwen2.5 + DeepSeek-V2)")
        from phases.phase6_agents.graph import run_debate

        patcher = PatchApplicator()

        for k, chunk in enumerate(final_chunks):
            logger.info(f"Processing Chunk {k+1}/{len(final_chunks)}: {chunk.chunk.name}")

            # Format the Semgrep info
            finding_strs = [f"Severity: {f.severity}\nMessage: {f.message}" for f in chunk.findings]
            semgrep_text = "\n".join(finding_strs)

            # --- PER-FINDING JOERN QUERY (targeted to this chunk's exact line) ---
            primary_line = chunk.findings[0].line_number if chunk.findings else chunk.chunk.start_line
            cpg_context = joern.analyze_finding(
                sink_line=primary_line,
                function_name=chunk.chunk.name
            )
            joern_context_str = cpg_context.to_prompt_context()

            try:
                # Run the LangGraph MoA debate with per-finding Joern context
                logger.info(f"Triggering Ollama models for {chunk.chunk.name}...")
                debate_results = await asyncio.to_thread(
                    run_debate,
                    original_code=chunk.chunk.content,
                    semgrep_finding=semgrep_text,
                    rag_context=chunk.rag_context or "No RAG context found.",
                    joern_context=joern_context_str,
                )
            except Exception as ml_err:
                logger.error(f"Failed to execute Phase 6 Agent Workflow: {ml_err}")
                logger.error("Ensure OLLAMA is running and models are pulled and have enough RAM/VRAM.")
                # Graceful Fallback if Ollama crashes
                debate_results = {
                    "attacker_exploit": "MoA Agent generation failed due to local Ollama crash/error.",
                    "final_secure_patch": "No patch available. Local LLM offline.",
                    "judge_verdict": "FAIL"
                }

            try:
                # Build vulnerability report entry with real ML confidence
                ml_result = ml_predictions.get(chunk.chunk.name, {})
                vuln_report = VulnerabilityReport(
                    file_path=chunk.chunk.file_path,
                    function_name=chunk.chunk.name,
                    start_line=chunk.chunk.start_line,
                    end_line=chunk.chunk.end_line,
                    vulnerability_type=chunk.findings[0].message if chunk.findings else "Unknown",
                    severity=chunk.findings[0].severity if chunk.findings else "MEDIUM",
                    cwe_id=chunk.findings[0].rule_id if chunk.findings else "Unknown",
                    semgrep_rule=chunk.findings[0].rule_id if chunk.findings else "",
                    rag_context=chunk.rag_context or "",
                    joern_taint_flow=joern_context_str,
                    ml_fusion_verdict=ml_result.get("prediction", "true_positive"),
                    ml_fusion_confidence=ml_result.get("confidence", 0.0),
                    attacker_exploit=debate_results.get("attacker_exploit", ""),
                    defender_patch=debate_results.get("final_secure_patch", ""),
                    judge_verdict=debate_results.get("judge_verdict", "PASS"),
                )

                # --- INTERACTIVE HUMAN-IN-THE-LOOP ---
                if "Ollama crash" not in debate_results["attacker_exploit"]:
                    print("\n" + "=" * 60)
                    print("🛡️  AI SECURITY PATCH PROPOSED 🛡️")
                    print("=" * 60)
                    print("--- ORIGINAL VULNERABLE CODE ---")
                    print(chunk.chunk.content)
                    print("\n--- ATTACKER'S EXPLOIT THREAT ---")
                    print(debate_results["attacker_exploit"])
                    print("\n--- DEFENDER'S FINAL SECURE PATCH (DeepSeek-V2) ---")
                    print(debate_results["final_secure_patch"])
                    print("=" * 60)
                    
                    # If running as FastAPI, we skip interactive input to avoid blocking the server indefinitely
                    user_approval = 'N'  # Default to No in headless mode (you could handle this differently via API)
                    vuln_report.human_approved = False
                else:
                    user_approval = 'N'
                    vuln_report.human_approved = False

                # --- RLHF TELEMETRY ---
                feedback_entry = {
                    "vulnerability_description": semgrep_text,
                    "rag_context": chunk.rag_context,
                    "joern_context": joern_context_str,
                    "original_code": chunk.chunk.content,
                    "generated_patch": debate_results.get("final_secure_patch", ""),
                    "human_approved": False
                }

                with open("training_dataset.jsonl", "a", encoding="utf-8") as f:
                    f.write(json.dumps(feedback_entry) + "\n")
                
                # --- PHASE 7: PATCH APPLICATION ---
                if user_approval == 'Y' and auto_patch:
                    success = patcher.apply_patch(
                        file_path=chunk.chunk.file_path,
                        original_code=chunk.chunk.content,
                        patched_code=debate_results["final_secure_patch"],
                        start_line=chunk.chunk.start_line,
                        end_line=chunk.chunk.end_line,
                    )
                    vuln_report.patch_applied = success
                    if success:
                        report.patches_applied += 1
                    else:
                        report.patches_rejected += 1

                report.vulnerabilities.append(vuln_report)

            except Exception as e:
                logger.error(f"Fatal error processing chunk {chunk.chunk.name}: {e}")

    # Cleanup Joern client
    joern.close()

    # --- PHASE 10: REPORT GENERATION ---
    logger.info("═" * 60)
    logger.info("[Phase 10] Security Report Generation")

    json_path = report_gen.generate_json_report(report)
    html_path = report_gen.generate_html_report(report)

    logger.info(f"📄 JSON Report: {json_path}")
    logger.info(f"🌐 HTML Report: {html_path}")

    logger.info("🏁 Pipeline Execution Complete.")

    return {
        "status": "complete",
        "total_files_scanned": report.total_files_scanned,
        "total_findings": report.total_static_findings,
        "findings_after_ml_filter": report.findings_after_ml_filter,
        "vulnerabilities_confirmed": len(report.vulnerabilities),
        "patches_applied": report.patches_applied,
        "report_path": json_path,
    }


# ============================================================
# API Endpoints
# ============================================================
@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_repo(request: AnalyzeRequest):
    """Trigger a full security analysis on a repository."""
    try:
        result = await run_pipeline(
            target_repo=request.repo_url,
            auto_patch=request.auto_patch,
        )
        return AnalyzeResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze-file", response_model=AnalyzeResponse)
async def analyze_file(file: UploadFile = File(...), auto_patch: bool = Form(False)):
    """Trigger a full security analysis on an uploaded ZIP file."""
    try:
        import shutil
        os.makedirs("./workspace", exist_ok=True)
        file_path = f"./workspace/{file.filename}"
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        result = await run_pipeline(
            target_repo=file_path,
            auto_patch=auto_patch,
        )
        return AnalyzeResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    import httpx
    ollama_status = "unknown"
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get("http://localhost:11434", timeout=3.0)
            ollama_status = "running" if resp.status_code == 200 else "unreachable"
    except Exception:
        ollama_status = "unreachable"

    return {
        "status": "healthy",
        "ollama": ollama_status,
        "pipeline_version": "2.0.0 (MoA Architecture)",
    }


# ============================================================
# CLI Entrypoint (backward compatible)
# ============================================================
if __name__ == "__main__":
    import sys

    if "--serve" in sys.argv:
        # Run as FastAPI server
        import uvicorn
        uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
    else:
        # Run as CLI pipeline (original behavior, enhanced)
        target = sys.argv[1] if len(sys.argv) > 1 else "https://github.com/pallets/flask"
        auto_patch = "--auto-patch" in sys.argv
        asyncio.run(run_pipeline(target, auto_patch=auto_patch))
