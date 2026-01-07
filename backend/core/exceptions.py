"""Custom exceptions for the application."""

class ScanException(Exception):
    """Base exception for scan operations."""
    pass

class MalwareDetectedException(ScanException):
    """Raised when malware is detected."""
    pass

class InvalidFileException(ScanException):
    """Raised when file is invalid."""
    pass

class ScanTimeoutException(ScanException):
    """Raised when scan times out."""
    pass

class IntegrationException(Exception):
    """Base exception for external integrations."""
    pass

class VirusTotalException(IntegrationException):
    """VirusTotal API error."""
    pass

class DatabaseException(Exception):
    """Database operation error."""
    pass
