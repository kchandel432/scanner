from pydantic import BaseModel

class AnalysisRequest(BaseModel):
    text: str

class AnalysisResult(BaseModel):
    summary: str
    malicious_score: float
