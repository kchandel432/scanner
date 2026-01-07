from fastapi import APIRouter

router = APIRouter()

@router.get("/latest")
async def latest_report():
    return {"report": "no-reports-yet"}
