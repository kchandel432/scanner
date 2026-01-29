from fastapi import FastAPI

app = FastAPI()


@app.get("/")
def root():
    return {"status": "Malware Scanner API is running"}
