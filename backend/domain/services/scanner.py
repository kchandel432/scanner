from abc import ABC, abstractmethod

class ScannerService(ABC):
    @abstractmethod
    def scan_file(self, path: str) -> dict:
        pass
