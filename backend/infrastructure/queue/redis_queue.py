"""
Redis-based task queue for async processing
"""
import asyncio
import json
import uuid
from typing import Dict, Any, Optional, Callable, List
from datetime import datetime
from enum import Enum

from backend.infrastructure.cache.redis_client import redis_client
from backend.core.logger import logger

class TaskStatus(str, Enum):
    """Task status"""
    PENDING = "pending"
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class TaskPriority(int, Enum):
    """Task priority levels"""
    LOW = 1
    NORMAL = 5
    HIGH = 10
    CRITICAL = 15

class TaskQueue:
    """Async task queue using Redis"""
    
    def __init__(self, queue_name: str = "default"):
        self.queue_name = f"queue:{queue_name}"
        self.processing_set = f"processing:{queue_name}"
        self.results_key = f"results:{queue_name}"
        
    async def enqueue(
        self,
        task_type: str,
        data: Dict[str, Any],
        priority: TaskPriority = TaskPriority.NORMAL,
        delay: int = 0
    ) -> str:
        """Enqueue a new task"""
        task_id = str(uuid.uuid4())
        
        task = {
            "id": task_id,
            "type": task_type,
            "data": data,
            "priority": priority,
            "status": TaskStatus.QUEUED,
            "created_at": datetime.utcnow().isoformat(),
            "queued_at": datetime.utcnow().isoformat(),
            "attempts": 0,
            "max_attempts": 3,
            "delay": delay
        }
        
        # Store task details
        await redis_client.hset(self.results_key, task_id, task)
        
        if delay > 0:
            # Delayed task
            score = asyncio.get_event_loop().time() + delay
            await redis_client.client.zadd(f"delayed:{self.queue_name}", {task_id: score})
        else:
            # Immediate task - use priority as score (lower = higher priority in Redis)
            score = -priority  # Negative because Redis ZSET sorts ascending
            await redis_client.client.zadd(self.queue_name, {task_id: score})
        
        logger.info(f"Task enqueued: {task_type} - {task_id}")
        return task_id
    
    async def dequeue(self) -> Optional[Dict[str, Any]]:
        """Dequeue the highest priority task"""
        try:
            # Get task ID from queue
            result = await redis_client.client.zpopmin(self.queue_name)
            if not result:
                return None
            
            task_id = result[0]
            
            # Move to processing set
            await redis_client.client.zadd(self.processing_set, {task_id: asyncio.get_event_loop().time()})
            
            # Get task details
            task = await redis_client.hget(self.results_key, task_id)
            if not task:
                return None
            
            task["status"] = TaskStatus.PROCESSING
            task["started_at"] = datetime.utcnow().isoformat()
            task["attempts"] = task.get("attempts", 0) + 1
            
            # Update task status
            await redis_client.hset(self.results_key, task_id, task)
            
            return task
            
        except Exception as e:
            logger.error(f"Dequeue error: {e}")
            return None
    
    async def complete(self, task_id: str, result: Dict[str, Any]):
        """Mark task as completed"""
        task = await redis_client.hget(self.results_key, task_id)
        if task:
            task["status"] = TaskStatus.COMPLETED
            task["completed_at"] = datetime.utcnow().isoformat()
            task["result"] = result
            
            # Remove from processing set
            await redis_client.client.zrem(self.processing_set, task_id)
            
            # Update task
            await redis_client.hset(self.results_key, task_id, task)
            
            # Publish completion event
            await redis_client.publish_scan_update(f"task:{task_id}", {
                "task_id": task_id,
                "status": "completed",
                "result": result
            })
    
    async def fail(self, task_id: str, error: str):
        """Mark task as failed"""
        task = await redis_client.hget(self.results_key, task_id)
        if task:
            task["status"] = TaskStatus.FAILED
            task["failed_at"] = datetime.utcnow().isoformat()
            task["error"] = error
            
            # Check if we should retry
            if task["attempts"] < task.get("max_attempts", 3):
                # Requeue with backoff
                backoff = 2 ** task["attempts"]  # Exponential backoff
                await self.enqueue(
                    task["type"],
                    task["data"],
                    priority=task["priority"],
                    delay=backoff
                )
            else:
                # Final failure
                await redis_client.client.zrem(self.processing_set, task_id)
            
            # Update task
            await redis_client.hset(self.results_key, task_id, task)
            
            # Publish failure event
            await redis_client.publish_scan_update(f"task:{task_id}", {
                "task_id": task_id,
                "status": "failed",
                "error": error
            })
    
    async def get_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get task status"""
        return await redis_client.hget(self.results_key, task_id)
    
    async def cancel(self, task_id: str) -> bool:
        """Cancel a pending task"""
        # Remove from queue
        removed = await redis_client.client.zrem(self.queue_name, task_id)
        
        if removed:
            task = await redis_client.hget(self.results_key, task_id)
            if task:
                task["status"] = TaskStatus.CANCELLED
                task["cancelled_at"] = datetime.utcnow().isoformat()
                await redis_client.hset(self.results_key, task_id, task)
            
            return True
        return False
    
    async def cleanup(self, max_age_hours: int = 24):
        """Cleanup old tasks"""
        cutoff = datetime.utcnow().timestamp() - (max_age_hours * 3600)
        
        # Get all tasks
        tasks = await redis_client.hgetall(self.results_key)
        
        for task_id, task in tasks.items():
            created_at = datetime.fromisoformat(task.get("created_at", "1970-01-01")).timestamp()
            if created_at < cutoff:
                # Remove old task
                await redis_client.client.zrem(self.queue_name, task_id)
                await redis_client.client.zrem(self.processing_set, task_id)
                await redis_client.hset(self.results_key, task_id, None)

async def init_queue():
    """Initialize task queue system"""
    # Start delayed tasks processor
    asyncio.create_task(process_delayed_tasks())

async def process_delayed_tasks():
    """Process delayed tasks"""
    while True:
        try:
            # Check for delayed tasks
            now = asyncio.get_event_loop().time()
            
            # Get ready delayed tasks
            ready_tasks = await redis_client.client.zrangebyscore(
                "delayed:queue:default",
                0,
                now
            )
            
            for task_id in ready_tasks:
                # Move to main queue
                await redis_client.client.zrem("delayed:queue:default", task_id)
                
                task = await redis_client.hget("results:queue:default", task_id)
                if task:
                    score = -task.get("priority", TaskPriority.NORMAL)
                    await redis_client.client.zadd("queue:default", {task_id: score})
            
            await asyncio.sleep(1)  # Check every second
            
        except Exception as e:
            logger.error(f"Delayed task processor error: {e}")
            await asyncio.sleep(5)
