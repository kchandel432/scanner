import asyncio
import sys

# Check if websockets is installed
try:
    import websockets
except ImportError:
    print("❌ 'websockets' library is missing. Install it with: pip install websockets")
    sys.exit(1)

async def test_websocket():
    # URL matching the one in WEBSOCKET_FIXED.md logs
    uri = "ws://localhost:8000/ws?client_id=test_script"
    print(f"Connecting to {uri}...")
    
    try:
        async with websockets.connect(uri) as websocket:
            print("✅ Connected to WebSocket server")
            
            # Wait for welcome message or send ping
            try:
                message = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                print(f"✅ Received message: {message}")
            except asyncio.TimeoutError:
                print("⚠️  Timeout waiting for message (connection is open though)")
            
            print("✅ WebSocket test passed!")
            return True
    except ConnectionRefusedError:
        print("❌ Connection refused. Is the backend running on port 8000?")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    success = asyncio.run(test_websocket())
    sys.exit(0 if success else 1)