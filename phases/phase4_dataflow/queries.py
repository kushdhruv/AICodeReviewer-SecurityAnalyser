"""
Joern Scala Query Templates
Each function builds a targeted Scala query for the Joern REPL / HTTP API.
Queries are per-finding (targeted to specific line numbers) rather than global.
"""


def build_taint_query(sink_line: int) -> str:
    """
    Builds Joern query to find all taint flows reaching a specific sink line.
    
    Strategy:
    1. Locate the exact sink call at the given line number
    2. Use all identifiers in the CPG as potential sources (comprehensive)
    3. Execute reachableByFlows to trace data propagation
    4. Map results to structured JSON with line numbers and code snippets
    """
    return f"""
    val sink = cpg.call.lineNumber({sink_line}).l
    val source = cpg.identifier.l
    
    val flows = sink.reachableByFlows(source).map {{ flow =>
        flow.elements.map {{ node =>
            Map("line" -> node.lineNumber.getOrElse(-1), "code" -> node.code)
        }}.toList
    }}.toList
    
    flows.toJson
    """.strip()


def build_sensitive_sink_query() -> str:
    """
    Finds all sensitive sinks in the codebase (SQL execute, OS commands, eval, etc.)
    Useful for initial triage before per-finding analysis.
    """
    return """
    cpg.call.name(".*execute.*|.*query.*|.*system.*|.*eval.*|.*exec.*|.*popen.*|.*open.*")
    .map { c =>
        Map(
            "name" -> c.name,
            "file" -> c.location.filename,
            "line" -> c.lineNumber.getOrElse(-1),
            "code" -> c.code
        )
    }.toJson
    """.strip()


def build_method_summary_query(method_name: str) -> str:
    """
    Builds a query to get the full call chain for a specific method/function.
    Shows what the method calls (callees) and what calls it (callers).
    """
    return f"""
    val target = cpg.method.name("{method_name}").l
    
    val callees = target.flatMap(_.callOut.callee.fullName.l).distinct
    val callers = target.flatMap(_.callIn.method.fullName.l).distinct
    
    Map(
        "method" -> "{method_name}",
        "calls" -> callees,
        "called_by" -> callers
    ).toJson
    """.strip()
