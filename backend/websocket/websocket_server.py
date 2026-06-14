from fastapi import WebSocket
from typing import List, Dict


class ConnectionManager:
    def __init__(self):
        # Maps user_email → list of their active WebSocket connections
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, user_email: str):
        await websocket.accept()
        if user_email not in self.active_connections:
            self.active_connections[user_email] = []
        self.active_connections[user_email].append(websocket)
        total = sum(len(v) for v in self.active_connections.values())
        print(f"🔌 WebSocket connected: {user_email}. Total connections: {total}")

    def disconnect(self, websocket: WebSocket, user_email: str):
        if user_email in self.active_connections:
            conns = self.active_connections[user_email]
            if websocket in conns:
                conns.remove(websocket)
            if not conns:
                del self.active_connections[user_email]
        total = sum(len(v) for v in self.active_connections.values())
        print(f"🔌 WebSocket disconnected: {user_email}. Total connections: {total}")

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast_to_user(self, message: str, user_email: str):
        """Send a message only to the connections belonging to a specific user."""
        conns = self.active_connections.get(user_email, [])
        dead  = []
        for connection in conns:
            try:
                await connection.send_text(message)
            except Exception:
                dead.append(connection)
        for conn in dead:
            self.disconnect(conn, user_email)

    async def broadcast(self, message: str, user_email: str = ""):
        """
        If user_email is provided, broadcast only to that user's connections.
        This ensures threat alerts are never sent to other users' sessions.
        """
        if user_email:
            await self.broadcast_to_user(message, user_email)
        else:
            # Fallback: send to all connections (used only for system-level messages)
            all_conns = [ws for conns in self.active_connections.values() for ws in conns]
            dead = []
            for connection in all_conns:
                try:
                    await connection.send_text(message)
                except Exception:
                    dead.append(connection)
            for conn in dead:
                for email, conns in list(self.active_connections.items()):
                    if conn in conns:
                        self.disconnect(conn, email)
                        break