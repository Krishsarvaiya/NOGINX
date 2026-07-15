"""Persistent WebSocket test client for the live analyzer.

Run this in a separate terminal to maintain a single stable WebSocket connection
and print any incoming JSON messages from the analyzer.

Usage:
  python scripts/test_ws_client.py
"""
import asyncio
import json

import websockets


async def run():
    uri = "ws://127.0.0.1:8765"
    print(f"Connecting to {uri}")
    try:
        async with websockets.connect(uri) as ws:
            print("Connected, waiting for messages...")
            while True:
                msg = await ws.recv()
                try:
                    obj = json.loads(msg)
                    print(json.dumps(obj, indent=2))
                except Exception:
                    print("raw:", msg)
    except Exception as e:
        print("Connection failed:", e)


if __name__ == "__main__":
    asyncio.run(run())
