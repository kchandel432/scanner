from fastapi import APIRouter

router = APIRouter()

@router.post("/analyze")
async def analyze_text(text: str):
    # placeholder AI analysis
    return {"text": text, "analysis": {"malicious_score": 0.1}}
