"""
HTMX routes for dynamic partial updates
"""
from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(prefix="/api/htmx", tags=["htmx"])

@router.get("/scan-status", response_class=HTMLResponse)
async def get_scan_status():
    """Get scan status partial"""
    return """
    <div id="scan-status" class="bg-gray-800 rounded-lg border border-gray-700 p-4">
        <div class="flex justify-between items-center mb-3">
            <span class="text-gray-300 font-semibold">Scan Progress</span>
            <span class="text-blue-400">45%</span>
        </div>
        <div class="w-full bg-gray-700 rounded-full h-2">
            <div class="bg-blue-500 h-2 rounded-full transition-all" style="width: 45%"></div>
        </div>
        <div class="mt-3 text-sm text-gray-400">
            <p>Status: <span class="text-white">Scanning...</span></p>
            <p>Elapsed: <span class="text-white">2:45 minutes</span></p>
        </div>
    </div>
    """

@router.get("/live-logs", response_class=HTMLResponse)
async def get_live_logs():
    """Get live logs partial"""
    return """
    <div id="live-logs" class="bg-gray-800 rounded-lg border border-gray-700 p-4 max-h-64 overflow-y-auto">
        <h3 class="text-white font-semibold mb-3">Live Logs</h3>
        <div class="space-y-2 font-mono text-xs">
            <p class="text-gray-400">[2024-01-04 12:00:15] Initializing scan engine...</p>
            <p class="text-gray-400">[2024-01-04 12:00:16] Loading malware signatures...</p>
            <p class="text-gray-400">[2024-01-04 12:00:17] Starting file analysis...</p>
            <p class="text-blue-400">[2024-01-04 12:00:18] Processing: file.exe</p>
            <p class="text-yellow-400">[2024-01-04 12:00:19] Warning: Suspicious behavior detected</p>
        </div>
    </div>
    """

@router.get("/risk-chart", response_class=HTMLResponse)
async def get_risk_chart():
    """Get risk distribution chart partial"""
    return """
    <div id="risk-chart" class="bg-gray-800 rounded-lg border border-gray-700 p-4">
        <h3 class="text-white font-semibold mb-4">Risk Distribution</h3>
        <div class="flex items-end gap-2 h-32">
            <div class="flex-1 bg-green-500 rounded-t" style="height: 65%"></div>
            <div class="flex-1 bg-yellow-500 rounded-t" style="height: 20%"></div>
            <div class="flex-1 bg-orange-500 rounded-t" style="height: 12%"></div>
            <div class="flex-1 bg-red-500 rounded-t" style="height: 3%"></div>
        </div>
        <div class="flex justify-between text-xs text-gray-400 mt-2">
            <span>Clean</span>
            <span>Low</span>
            <span>Med</span>
            <span>High</span>
        </div>
    </div>
    """

# Export router
htmx_router = router
