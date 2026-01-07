from fastapi import APIRouter

router = APIRouter()

@router.post("/check")
async def check_website(url: str):
    # placeholder website scanning
    return {"url": url, "status": "ok"}
