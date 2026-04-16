import os
import json
from pathlib import Path
from typing import List, Dict, Any

import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer

from utils.logger import get_logger
from phases.phase3_scanning.scanner import EnrichedCodeChunk

logger = get_logger(__name__)

class VulnerabilityDatabase:
    """
    Phase 5 RAG Database using ChromaDB and BGE-Small embeddings.
    Manages the ingestion and querying of CWE/CVE semantic data.
    """
    
    def __init__(self, db_path: str = "./workspace/vector_db"):
        self.db_path = Path(db_path)
        self.db_path.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Initializing ChromaDB at {self.db_path}")
        self.chroma_client = chromadb.PersistentClient(
            path=str(self.db_path),
            settings=Settings(anonymized_telemetry=False)
        )
        
        # Load the BGE-Small model. It will auto-download on first run.
        logger.info("Loading bge-small-en-v1.5 Embedding Model...")
        self.embedder = SentenceTransformer("BAAI/bge-small-en-v1.5")
        
        # Get or create the collection
        self.collection = self.chroma_client.get_or_create_collection(
            name="cwe_knowledge",
            metadata={"hnsw:space": "cosine"} # Cosine similarity is best for semantic text
        )

    def _generate_embedding(self, text: str) -> List[float]:
        """Generates a 384-dimensional vector using BGE-Small."""
        return self.embedder.encode(text).tolist()

    def build_knowledge_base(self, json_path: str):
        """
        Reads the CWE JSON and executes targeted sub-concept chunking (Root Cause, Mitigation).
        Only populates if the DB is empty.
        """
        if self.collection.count() > 0:
            logger.info(f"Knowledge Base already populated with {self.collection.count()} chunks. Skipping ingestion.")
            return

        logger.info(f"Building Knowledge Base from {json_path}")
        
        with open(json_path, 'r', encoding='utf-8') as f:
            cwe_data = json.load(f)

        ids = []
        documents = []
        embeddings = []
        metadatas = []

        # Sub-Concept Chunking Strategy
        for i, cwe in enumerate(cwe_data):
            cwe_id = cwe.get("cwe_id")
            name = cwe.get("name")
            
            # --- CHUNK 1: The Root Cause ---
            rc_text = f"[{cwe_id} - {name}] Root Cause: {cwe.get('root_cause')}"
            documents.append(rc_text)
            embeddings.append(self._generate_embedding(rc_text))
            metadatas.append({"cwe_id": cwe_id, "type": "root_cause"})
            ids.append(f"{cwe_id}_root_cause")

            # --- CHUNK 2: The Mitigation ---
            # We join the array into a paragraph
            mit_str = " ".join(cwe.get("mitigation", []))
            mit_text = f"[{cwe_id} - {name}] Mitigation: {mit_str}"
            documents.append(mit_text)
            embeddings.append(self._generate_embedding(mit_text))
            metadatas.append({"cwe_id": cwe_id, "type": "mitigation"})
            ids.append(f"{cwe_id}_mitigation")
            
            # --- CHUNK 3: Context / CVE ---
            cve_str = " ".join(cwe.get("cve_examples", []))
            context_text = f"[{cwe_id} - {name}] Definition: {cwe.get('definition')} Examples: {cve_str}"
            documents.append(context_text)
            embeddings.append(self._generate_embedding(context_text))
            metadatas.append({"cwe_id": cwe_id, "type": "context"})
            ids.append(f"{cwe_id}_context")

        logger.info(f"Injecting {len(documents)} Sub-Concept Chunks into ChromaDB...")
        self.collection.add(
            ids=ids,
            embeddings=embeddings,
            documents=documents,
            metadatas=metadatas
        )
        logger.info("Knowledge Base insertion complete.")

    def enhance_chunks(self, vulnerable_chunks: List[EnrichedCodeChunk]) -> List[EnrichedCodeChunk]:
        """
        Takes the Phase 3 chunks and queries the DB to attach Phase 5 Semantic definitions.
        """
        logger.info("Executing Hybrid Semantic Queries against Knowledge Base...")
        
        for chunk in vulnerable_chunks:
            # We only query if there are findings
            if not chunk.findings:
                continue
                
            # Create a hybrid query string for the LLM
            # We combine the Semgrep message and the actual vulnerable function code
            # We take just a slice of the code if it's too long
            code_snippet = chunk.chunk.content[:300] if len(chunk.chunk.content) > 300 else chunk.chunk.content
            
            # Find the highest severity finding to build the query
            primary_finding = chunk.findings[0] # Just using the first one for simplicity right now
            
            query_text = f"Vulnerability: {primary_finding.message}\nCode Context: {code_snippet}"
            
            # Generate hybrid embedding
            query_embedding = self._generate_embedding(query_text)
            
            # Retrieve Top 3 chunks
            results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=3,
                # Example Metadata Filtering (if we had strict keywords, we could filter here)
                # where={"cwe_id": {"$in": ["CWE-89"]}}
            )
            
            # Ensure the chunk has a dynamic attribute to hold RAG data later for the LLM
            # We just append it to a raw dictionary to be converted to str later
            extracted_docs = results.get('documents', [[]])[0]
            chunk.rag_context = "\n---\n".join(extracted_docs)
            
        logger.info(f"Successfully attached local RAG context to {len(vulnerable_chunks)} chunks.")
        return vulnerable_chunks


# Module-level singleton to avoid re-loading the SentenceTransformer model
_RAG_DB_INSTANCE = None

def get_rag_database(
    db_path: str = "./workspace/vector_db",
    knowledge_path: str = "phases/phase5_rag/cwe_knowledge.json"
) -> VulnerabilityDatabase:
    """
    Returns a singleton VulnerabilityDatabase instance.
    Avoids re-loading the BGE-Small model on every pipeline run.
    """
    global _RAG_DB_INSTANCE
    if _RAG_DB_INSTANCE is None:
        _RAG_DB_INSTANCE = VulnerabilityDatabase(db_path=db_path)
        _RAG_DB_INSTANCE.build_knowledge_base(knowledge_path)
    return _RAG_DB_INSTANCE
