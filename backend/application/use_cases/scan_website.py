from backend.application.services.website_scanner import WebsiteScanner

def handle_scan_website(url: str):
    scanner = WebsiteScanner()
    return scanner.check(url)
