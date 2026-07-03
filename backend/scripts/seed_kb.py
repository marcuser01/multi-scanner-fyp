import os
import chromadb
from chromadb.utils import embedding_functions

# Use a simple embedding function (no API key required for local embedding)
default_ef = embedding_functions.DefaultEmbeddingFunction()

# Initialize ChromaDB client and collection
client = chromadb.PersistentClient(path="./backend/data/chroma_db")
collection = client.get_or_create_collection(name="security_kb", embedding_function=default_ef)

def seed_knowledge_base():
    kb_base_path = "./knowledge_base"
    
    # os.walk allows us to go into subfolders (cwe, owasp, etc.)
    for root, dirs, files in os.walk(kb_base_path):
        for filename in files:
            if filename.endswith(".md"):
                # Construct the full file path
                file_path = os.path.join(root, filename)
                
                # Determine category based on the immediate parent folder name
                category = os.path.basename(root)
                
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                    # Create a unique ID using the category and filename 
                    # (e.g., "cwe/cwe-122.md") to prevent collisions
                    unique_id = f"{category}/{filename}"
                    
                    collection.add(
                        documents=[content],
                        metadatas=[{
                            "source": filename,
                            "category": category,
                            "path": file_path
                        }],
                        ids=[unique_id]
                    )
                    print(f"Added: {unique_id}")

    print(f"\nSuccessfully seeded Knowledge Base from {kb_base_path}")

if __name__ == "__main__":
    seed_knowledge_base()