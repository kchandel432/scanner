from backend.application.services.malware_scanner import MalwareScanner

def handle_scan_file(file_path: str):
    scanner = MalwareScanner()
    return scanner.scan_file(file_path)
