"""
Redis client for caching and pub/sub
"""
import json
import asyncio
from typing import Any, Optional, Dict, List
import redis.asyncio as redis
from redis.asyncio.client import Redis
from backend.core.settings import settings
from backend.core.logger import logger

class RedisClient:
    """Async Redis client with connection pooling"""
    
    def __init__(self):
        self.client: Optional[Redis] = None
        self.pubsub = None
        
    async def initialize(self):
        """Initialize Redis connection"""
        try:
            self.client = redis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
                socket_keepalive=True,
                socket_timeout=5,
                retry_on_timeout=True,
                max_connections=20,
            )
            
            # Test connection
            await self.client.ping()
            logger.info("✅ Redis connected successfully")
            
        except Exception as e:
            logger.error(f"❌ Redis connection failed: {e}")
            raise
    
    async def close(self):
        """Close Redis connection"""
        if self.client:
            await self.client.close()
            logger.info("✅ Redis connection closed")
    
    # Key-Value operations
    async def set(self, key: str, value: Any, expire: Optional[int] = None) -> bool:
        """Set key-value with optional expiration"""
        try:
            serialized = json.dumps(value)
            if expire:
                await self.client.setex(key, expire, serialized)
            else:
                await self.client.set(key, serialized)
            return True
        except Exception as e:
            logger.error(f"Redis set error: {e}")
            return False
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value by key"""
        try:
            value = await self.client.get(key)
            if value:
                return json.loads(value)
            return None
        except Exception as e:
            logger.error(f"Redis get error: {e}")
            return None
    
    async def delete(self, key: str) -> bool:
        """Delete key"""
        try:
            await self.client.delete(key)
            return True
        except Exception as e:
            logger.error(f"Redis delete error: {e}")
            return False
    
    async def exists(self, key: str) -> bool:
        """Check if key exists"""
        try:
            return await self.client.exists(key) > 0
        except Exception as e:
            logger.error(f"Redis exists error: {e}")
            return False
    
    # Hash operations
    async def hset(self, key: str, field: str, value: Any) -> bool:
        """Set hash field"""
        try:
            serialized = json.dumps(value)
            await self.client.hset(key, field, serialized)
            return True
        except Exception as e:
            logger.error(f"Redis hset error: {e}")
            return False
    
    async def hget(self, key: str, field: str) -> Optional[Any]:
        """Get hash field"""
        try:
            value = await self.client.hget(key, field)
            if value:
                return json.loads(value)
            return None
        except Exception as e:
            logger.error(f"Redis hget error: {e}")
            return None
    
    async def hgetall(self, key: str) -> Dict[str, Any]:
        """Get all hash fields"""
        try:
            data = await self.client.hgetall(key)
            return {k: json.loads(v) for k, v in data.items()}
        except Exception as e:
            logger.error(f"Redis hgetall error: {e}")
            return {}
    
    # List operations
    async def lpush(self, key: str, value: Any) -> bool:
        """Push to list"""
        try:
            serialized = json.dumps(value)
            await self.client.lpush(key, serialized)
            return True
        except Exception as e:
            logger.error(f"Redis lpush error: {e}")
            return False
    
    async def rpush(self, key: str, value: Any) -> bool:
        """Push to end of list"""
        try:
            serialized = json.dumps(value)
            await self.client.rpush(key, serialized)
            return True
        except Exception as e:
            logger.error(f"Redis rpush error: {e}")
            return False
    
    async def lrange(self, key: str, start: int = 0, end: int = -1) -> List[Any]:
        """Get list range"""
        try:
            data = await self.client.lrange(key, start, end)
            return [json.loads(item) for item in data]
        except Exception as e:
            logger.error(f"Redis lrange error: {e}")
            return []
    
    # Set operations
    async def sadd(self, key: str, value: Any) -> bool:
        """Add to set"""
        try:
            serialized = json.dumps(value)
            await self.client.sadd(key, serialized)
            return True
        except Exception as e:
            logger.error(f"Redis sadd error: {e}")
            return False
    
    async def smembers(self, key: str) -> List[Any]:
        """Get all set members"""
        try:
            data = await self.client.smembers(key)
            return [json.loads(item) for item in data]
        except Exception as e:
            logger.error(f"Redis smembers error: {e}")
            return []
    
    # Scan operations
    async def get_scan_progress(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get scan progress from Redis"""
        return await self.hget(f"scan:{scan_id}", "progress")
    
    async def set_scan_progress(self, scan_id: str, progress: Dict[str, Any]) -> bool:
        """Set scan progress in Redis"""
        return await self.hset(f"scan:{scan_id}", "progress", progress)
    
    async def publish_scan_update(self, scan_id: str, data: Dict[str, Any]):
        """Publish scan update to channel"""
        try:
            channel = f"scan_updates:{scan_id}"
            await self.client.publish(channel, json.dumps(data))
        except Exception as e:
            logger.error(f"Redis publish error: {e}")
    
    async def subscribe_to_scan(self, scan_id: str):
        """Subscribe to scan updates"""
        if not self.pubsub:
            self.pubsub = self.client.pubsub()
        
        channel = f"scan_updates:{scan_id}"
        await self.pubsub.subscribe(channel)
        return self.pubsub
    
    # Rate limiting
    async def check_rate_limit(self, key: str, limit: int, window: int) -> Dict[str, Any]:
        """Check rate limit using sliding window"""
        current_time = asyncio.get_event_loop().time()
        window_start = current_time - window
        
        try:
            # Remove old entries
            await self.client.zremrangebyscore(key, 0, window_start)
            
            # Count current requests
            count = await self.client.zcard(key)
            
            if count >= limit:
                # Get oldest request time
                oldest = await self.client.zrange(key, 0, 0, withscores=True)
                if oldest:
                    retry_after = int(window_start + window - current_time)
                    return {
                        "allowed": False,
                        "remaining": 0,
                        "reset_after": max(0, retry_after)
                    }
            
            # Add current request
            await self.client.zadd(key, {str(current_time): current_time})
            await self.client.expire(key, window)
            
            return {
                "allowed": True,
                "remaining": limit - count - 1,
                "reset_after": window
            }
            
        except Exception as e:
            logger.error(f"Rate limit error: {e}")
            return {"allowed": True, "remaining": limit, "reset_after": window}

# Global Redis client instance
redis_client = RedisClient()
