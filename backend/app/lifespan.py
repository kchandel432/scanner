"""
Application lifespan management
"""

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Callable, List


class LifespanManager:
    """Manages application startup and shutdown tasks"""

    def __init__(self):
        self.startup_tasks: List[Callable] = []
        self.shutdown_tasks: List[Callable] = []

    def add_startup_task(self, task: Callable):
        """Add a startup task"""
        self.startup_tasks.append(task)

    def add_shutdown_task(self, task: Callable):
        """Add a shutdown task"""
        self.shutdown_tasks.append(task)

    async def startup(self):
        """Execute all startup tasks"""
        for task in self.startup_tasks:
            try:
                if asyncio.iscoroutinefunction(task):
                    await task()
                else:
                    task()
            except Exception as e:
                print(f"Startup task failed: {e}")
                # Continue with other tasks even if one fails

    async def shutdown(self):
        """Execute all shutdown tasks"""
        for task in reversed(self.shutdown_tasks):
            try:
                if asyncio.iscoroutinefunction(task):
                    await task()
                else:
                    task()
            except Exception as e:
                print(f"Shutdown task failed: {e}")


# Global lifespan manager instance
lifespan = LifespanManager()
