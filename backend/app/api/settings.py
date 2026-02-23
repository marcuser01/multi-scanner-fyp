from fastapi import APIRouter, Body

router = APIRouter()

@router.post("/api-key")
async def save_key(key: str = Body(..., embed=True)):
    # In a real app, encrypt this. For MVP, we'll save to a .env or a local text file.
    with open("data/llm_key.txt", "w") as f:
        f.write(key)
    return {"message": "Key saved successfully"}