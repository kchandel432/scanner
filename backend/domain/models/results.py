from pydantic import BaseModel

class ReportItem(BaseModel):
    id: str
    summary: str
