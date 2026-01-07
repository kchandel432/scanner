"""
Background worker for scanning tasks
"""
import asyncio
import json
from typing import Dict, Any
from datetime import datetime

from backend.infrastructure.queue.redis_queue import TaskQueue, TaskStatus
from backend.infrastructure.cache.redis_client import redis_client
from backend.application.services.malware_scanner import MalwareScanner
from backend.application.services.website_engine import WebsiteScanner
from backend.domain.models.scan import ScanType
from backend.core.logger import logger

class ScannerWorker:
    """Worker for processing scan tasks"""
    
    def __init__(self):
        self.task_queue = TaskQueue("scans")
        self.malware_scanner = MalwareScanner()
        self.website_scanner = WebsiteScanner()
        self.running = False
        
    async def start(self):
        """Start the worker"""
        self.running = True
        logger.info("🚀 Scanner worker started")
        
        while self.running:
            try:
                # Get next task
                task = await self.task_queue.dequeue()
                
                if task:
                    # Process task
                    await self.process_task(task)
                else:
                    # No tasks, wait a bit
                    await asyncio.sleep(0.1)
                    
            except Exception as e:
                logger.error(f"Worker error: {e}")
                await asyncio.sleep(1)
    
    async def stop(self):
        """Stop the worker"""
        self.running = False
        logger.info("🛑 Scanner worker stopping")
    
    async def process_task(self, task: Dict[str, Any]):
        """Process a scan task"""
        task_id = task["id"]
        task_type = task["type"]
        
        logger.info(f"Processing task: {task_type} - {task_id}")
        
        try:
            if task_type == "file_scan":
                result = await self.process_file_scan(task)
            elif task_type == "website_scan":
                result = await self.process_website_scan(task)
            elif task_type == "portfolio_scan":
                result = await self.process_portfolio_scan(task)
            else:
                raise ValueError(f"Unknown task type: {task_type}")
            
            # Mark as completed
            await self.task_queue.complete(task_id, result)
            
            logger.info(f"Task completed: {task_type} - {task_id}")
            
        except Exception as e:
            logger.error(f"Task failed: {task_id} - {e}")
            await self.task_queue.fail(task_id, str(e))
    
    async def process_file_scan(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Process file scan task"""
        data = task["data"]
        file_path = data.get("file_path")
        file_content = data.get("file_content")
        
        if not file_path and not file_content:
            raise ValueError("No file provided")
        
        # Update progress
        await self.update_progress(task["id"], 10, "Starting file analysis...")
        
        # Scan file
        await self.update_progress(task["id"], 30, "Running static analysis...")
        result = await self.malware_scanner.scan_file(file_path, file_content)
        
        await self.update_progress(task["id"], 70, "Performing heuristic analysis...")
        
        await self.update_progress(task["id"], 90, "Generating report...")
        
        return {
            "success": True,
            "result": result.dict() if hasattr(result, 'dict') else result,
            "scan_type": ScanType.FILE,
            "completed_at": datetime.utcnow().isoformat()
        }
    
    async def process_website_scan(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Process website scan task"""
        data = task["data"]
        url = data.get("url")
        
        if not url:
            raise ValueError("No URL provided")
        
        # Update progress
        await self.update_progress(task["id"], 10, "Starting website analysis...")
        
        # Scan website
        await self.update_progress(task["id"], 30, "Checking SSL/TLS...")
        result = await self.website_scanner.scan_website(url)
        
        await self.update_progress(task["id"], 60, "Analyzing security headers...")
        
        await self.update_progress(task["id"], 80, "Checking for vulnerabilities...")
        
        await self.update_progress(task["id"], 95, "Generating security report...")
        
        return {
            "success": True,
            "result": result.dict() if hasattr(result, 'dict') else result,
            "scan_type": ScanType.WEBSITE,
            "completed_at": datetime.utcnow().isoformat()
        }
    
    async def process_portfolio_scan(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Process portfolio scan task"""
        data = task["data"]
        portfolio_id = data.get("portfolio_id")
        
        if not portfolio_id:
            raise ValueError("No portfolio ID provided")
        
        # This would fetch portfolio targets from database
        # For now, simulate scanning multiple targets
        targets = [
            {"id": "target_1", "url": "https://example.com"},
            {"id": "target_2", "url": "https://test.com"},
        ]
        
        results = []
        total_targets = len(targets)
        
        for i, target in enumerate(targets):
            progress = int((i / total_targets) * 90)
            await self.update_progress(
                task["id"],
                progress,
                f"Scanning target {i+1}/{total_targets}: {target['url']}"
            )
            
            try:
                result = await self.website_scanner.scan_website(target["url"])
                results.append({
                    "target_id": target["id"],
                    "result": result.dict() if hasattr(result, 'dict') else result
                })
            except Exception as e:
                results.append({
                    "target_id": target["id"],
                    "error": str(e)
                })
            
            await asyncio.sleep(1)  # Simulate processing time
        
        await self.update_progress(task["id"], 95, "Aggregating results...")
        
        # Calculate portfolio risk score
        risk_scores = [r["result"].get("risk_score", 0) for r in results if "result" in r]
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        
        return {
            "success": True,
            "portfolio_id": portfolio_id,
            "results": results,
            "summary": {
                "total_targets": total_targets,
                "scanned_targets": len(results),
                "avg_risk_score": avg_risk,
                "completed_at": datetime.utcnow().isoformat()
            }
        }
    
    async def update_progress(self, task_id: str, progress: int, message: str):
        """Update task progress"""
        try:
            await redis_client.set_scan_progress(task_id, {
                "progress": progress,
                "message": message,
                "updated_at": datetime.utcnow().isoformat()
            })
            
            # Publish update
            await redis_client.publish_scan_update(task_id, {
                "task_id": task_id,
                "progress": progress,
                "message": message,
                "timestamp": datetime.utcnow().isoformat()
            })
        except Exception as e:
            logger.error(f"Error updating progress: {e}")
        
        # Small delay to make progress visible
        await asyncio.sleep(0.1)

# Global worker instance
scanner_worker = ScannerWorker()

async def start_worker():
    """Start the scanner worker"""
    await scanner_worker.start()
