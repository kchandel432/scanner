from abc import ABC, abstractmethod

class AnalysisService(ABC):
    @abstractmethod
    def analyze(self, text: str) -> dict:
        pass
