"""
Phase 2: Code Parsing (Multi-Language)
Goal: Parse the raw text of code files and extract top-level functions/classes
using tree-sitter. Supports Python, JavaScript, TypeScript, Go, Java, and C/C++.
"""

from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional, Dict
from tree_sitter_languages import get_parser, get_language
from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class CodeChunk:
    """Standardized representation of an extracted code block."""
    file_path: str
    chunk_type: str  # 'function' or 'class'
    name: str
    start_line: int
    end_line: int
    content: str
    language: str


# ---- LANGUAGE CONFIGURATION ----
# Maps file extension → (tree-sitter language name, AST query, definition captures, name node type)

LANGUAGE_CONFIGS: Dict[str, dict] = {
    ".py": {
        "language": "python",
        "query": """
            (function_definition
                name: (identifier) @func.name) @func.def
            (class_definition
                name: (identifier) @class.name) @class.def
        """,
        "def_captures": {"func.def": "function", "class.def": "class"},
        "name_node_type": "identifier",
    },
    ".js": {
        "language": "javascript",
        "query": """
            (function_declaration
                name: (identifier) @func.name) @func.def
            (class_declaration
                name: (identifier) @class.name) @class.def
            (method_definition
                name: (property_identifier) @func.name) @func.def
        """,
        "def_captures": {"func.def": "function", "class.def": "class"},
        "name_node_type": {"identifier", "property_identifier"},
    },
    ".ts": {
        "language": "typescript",
        "query": """
            (function_declaration
                name: (identifier) @func.name) @func.def
            (class_declaration
                name: (type_identifier) @class.name) @class.def
            (method_definition
                name: (property_identifier) @func.name) @func.def
        """,
        "def_captures": {"func.def": "function", "class.def": "class"},
        "name_node_type": {"identifier", "type_identifier", "property_identifier"},
    },
    ".go": {
        "language": "go",
        "query": """
            (function_declaration
                name: (identifier) @func.name) @func.def
            (method_declaration
                name: (field_identifier) @func.name) @func.def
        """,
        "def_captures": {"func.def": "function"},
        "name_node_type": {"identifier", "field_identifier"},
    },
    ".java": {
        "language": "java",
        "query": """
            (method_declaration
                name: (identifier) @func.name) @func.def
            (class_declaration
                name: (identifier) @class.name) @class.def
        """,
        "def_captures": {"func.def": "function", "class.def": "class"},
        "name_node_type": "identifier",
    },
    ".c": {
        "language": "c",
        "query": """
            (function_definition
                declarator: (function_declarator
                    declarator: (identifier) @func.name)) @func.def
        """,
        "def_captures": {"func.def": "function"},
        "name_node_type": "identifier",
    },
    ".cpp": {
        "language": "cpp",
        "query": """
            (function_definition
                declarator: (function_declarator
                    declarator: (identifier) @func.name)) @func.def
            (class_specifier
                name: (type_identifier) @class.name) @class.def
        """,
        "def_captures": {"func.def": "function", "class.def": "class"},
        "name_node_type": {"identifier", "type_identifier"},
    },
}

# Alias extensions
LANGUAGE_CONFIGS[".jsx"] = LANGUAGE_CONFIGS[".js"]
LANGUAGE_CONFIGS[".tsx"] = LANGUAGE_CONFIGS[".ts"]
LANGUAGE_CONFIGS[".h"] = LANGUAGE_CONFIGS[".c"]
LANGUAGE_CONFIGS[".hpp"] = LANGUAGE_CONFIGS[".cpp"]
LANGUAGE_CONFIGS[".cc"] = LANGUAGE_CONFIGS[".cpp"]
LANGUAGE_CONFIGS[".cs"] = LANGUAGE_CONFIGS[".java"]  # C# has similar structure


class CodeParser:
    """
    Industry-grade AST parser using Tree-Sitter to extract structured blocks.
    Supports multi-language parsing via configurable query templates.
    """

    def __init__(self):
        # Cache parsed language/query objects to avoid re-initialization
        self._parsers = {}
        self._queries = {}

    def _get_parser_for_ext(self, ext: str):
        """Lazily initialize and cache parser + query for a file extension."""
        if ext not in LANGUAGE_CONFIGS:
            return None, None, None

        if ext not in self._parsers:
            config = LANGUAGE_CONFIGS[ext]
            lang_name = config["language"]
            try:
                parser = get_parser(lang_name)
                language = get_language(lang_name)
                query = language.query(config["query"])
                self._parsers[ext] = parser
                self._queries[ext] = (query, config)
                logger.info(f"  Initialized tree-sitter parser for {lang_name}")
            except Exception as e:
                logger.warning(f"  Failed to init parser for {lang_name}: {e}")
                self._parsers[ext] = None
                self._queries[ext] = (None, None)

        parser = self._parsers.get(ext)
        query_config = self._queries.get(ext, (None, None))
        return parser, query_config[0], query_config[1]

    def get_supported_extensions(self) -> set:
        """Return the set of file extensions this parser supports."""
        return set(LANGUAGE_CONFIGS.keys())

    def parse_file(self, file_path: Path) -> List[CodeChunk]:
        """
        Reads a file, constructs the AST, and executes tree-sitter queries
        to deterministically extract all function and class blocks.
        Supports multiple languages based on file extension.
        """
        extracted_chunks = []

        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return extracted_chunks

        ext = file_path.suffix.lower()
        parser, query, config = self._get_parser_for_ext(ext)

        if parser is None or query is None:
            # Unsupported extension — skip silently
            return extracted_chunks

        lang_name = config["language"]
        def_captures = config["def_captures"]
        name_node_types = config["name_node_type"]
        if isinstance(name_node_types, str):
            name_node_types = {name_node_types}

        try:
            # 1. Read bytes securely
            file_bytes = file_path.read_bytes()

            # 2. Build AST
            tree = parser.parse(file_bytes)
            root_node = tree.root_node

            # 3. Execute AST Query
            captures = query.captures(root_node)

            # Captures return a list of tuples: (node, capture_name)
            for node, capture_name in captures:

                # We only process the full definition blocks, not just the name nodes
                if capture_name in def_captures:
                    chunk_type = def_captures[capture_name]

                    # Look for the child node that represents the identifier (name)
                    name_node = next(
                        (n for n in node.children if n.type in name_node_types),
                        None
                    )
                    name = name_node.text.decode("utf8") if name_node else "anonymous"

                    chunk = CodeChunk(
                        file_path=str(file_path),
                        chunk_type=chunk_type,
                        name=name,
                        start_line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                        content=node.text.decode("utf8"),
                        language=lang_name,
                    )
                    extracted_chunks.append(chunk)

        except Exception as e:
            logger.exception(f"Critical failure parsing {file_path}: {e}")

        return extracted_chunks
