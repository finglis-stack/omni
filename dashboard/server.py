"""
OmniScan Dashboard Server
Real-time web dashboard with WebSocket for live scan monitoring,
interactive attack graph, and AI-powered analysis.
"""
import asyncio
import json
import os
import webbrowser
import threading
from aiohttp import web
from datetime import datetime


class DashboardServer:
    def __init__(self, host="127.0.0.1", port=8888):
        self.host = host
        self.port = port
        self.app = web.Application()
        self.clients = set()
        self.scan_results = {}
        self.scan_status = "idle"  # idle, running, complete
        self.scan_target = ""
        self.scan_config = {}
        self.ai_analyzer = None
        self.scanner_ref = None
        self.event_log = []

        static_dir = os.path.join(os.path.dirname(__file__), "static")
        self.app.router.add_get("/", self._serve_index)
        self.app.router.add_static("/static", static_dir)
        self.app.router.add_get("/ws", self._ws_handler)
        self.app.router.add_post("/api/scan/start", self._api_start_scan)
        self.app.router.add_get("/api/scan/status", self._api_scan_status)
        self.app.router.add_post("/api/ai/analyze", self._api_ai_analyze)
        self.app.router.add_get("/api/results", self._api_results)

    async def _serve_index(self, request):
        index_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
        return web.FileResponse(index_path)

    async def _ws_handler(self, request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        self.clients.add(ws)

        # Send current state to new client
        await ws.send_json({
            "type": "state",
            "status": self.scan_status,
            "target": self.scan_target,
            "results": self.scan_results,
            "events": self.event_log[-100:],
        })

        try:
            async for msg in ws:
                if msg.type == web.WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    if data.get("action") == "start_scan":
                        # If API key is provided in config, set it now
                        api_key = data.get("api_key", "")
                        if api_key and not self.ai_analyzer:
                            from core.ai_analyzer import AIAnalyzer
                            self.ai_analyzer = AIAnalyzer(api_key=api_key)
                        asyncio.create_task(self._run_scan(data))
                    elif data.get("action") == "ai_analyze":
                        # Accept API key with analyze request too
                        api_key = data.get("api_key", "")
                        if api_key:
                            from core.ai_analyzer import AIAnalyzer
                            self.ai_analyzer = AIAnalyzer(api_key=api_key)
                        asyncio.create_task(self._run_ai_analysis())
                    elif data.get("action") == "set_api_key":
                        from core.ai_analyzer import AIAnalyzer
                        self.ai_analyzer = AIAnalyzer(api_key=data.get("api_key", ""))
                        await ws.send_json({"type": "info", "data": {"message": "API key configured"}})
        finally:
            self.clients.discard(ws)
        return ws

    async def broadcast(self, message):
        """Send a message to all connected WebSocket clients."""
        dead = set()
        for ws in self.clients:
            try:
                await ws.send_json(message)
            except Exception:
                dead.add(ws)
        self.clients -= dead

    async def emit_event(self, event_type, data):
        """Emit a scan event to all clients."""
        event = {
            "type": event_type,
            "timestamp": datetime.now().isoformat(),
            "data": data,
        }
        self.event_log.append(event)
        await self.broadcast(event)

    async def _run_scan(self, config):
        """Run a scan from the dashboard."""
        if self.scan_status == "running":
            await self.broadcast({"type": "error", "data": {"message": "Scan already running"}})
            return

        self.scan_status = "running"
        self.scan_target = config.get("url", "")
        self.scan_config = config
        self.scan_results = {}
        self.event_log = []

        await self.broadcast({"type": "scan_started", "data": {"target": self.scan_target}})

        try:
            # Import here to avoid circular imports
            from omniscan import OmniScan

            scanner = OmniScan(
                target_url=self.scan_target,
                threads=int(config.get("threads", 5)),
                stealth=config.get("stealth", "light"),
                proxy=config.get("proxy") or None,
                impersonate=config.get("impersonate") or None,
            )
            scanner.dashboard = self  # Inject dashboard reference for event emission
            self.scanner_ref = scanner

            # Run the scan in a thread to avoid blocking the event loop
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, scanner.run)

            self.scan_results = dict(scanner.results)
            self.scan_status = "complete"
            await self.emit_event("scan_complete", {
                "total_findings": sum(
                    len(v) for k, v in self.scan_results.items()
                    if k not in ("endpoints", "forms") and isinstance(v, list)
                ),
                "endpoints": len(self.scan_results.get("endpoints", [])),
                "forms": len(self.scan_results.get("forms", [])),
            })

        except Exception as e:
            self.scan_status = "error"
            await self.emit_event("scan_error", {"message": str(e)})

    async def _run_ai_analysis(self):
        """Trigger AI analysis of scan results."""
        if not self.ai_analyzer:
            await self.broadcast({"type": "error", "data": {"message": "No API key configured"}})
            return
        if not self.scan_results:
            await self.broadcast({"type": "error", "data": {"message": "No scan results to analyze"}})
            return

        await self.emit_event("ai_started", {})

        try:
            analysis = await self.ai_analyzer.full_analysis(self.scan_target, self.scan_results)
            await self.emit_event("ai_complete", analysis)
        except Exception as e:
            await self.emit_event("ai_error", {"message": str(e)})

    # ─── REST API ───

    async def _api_start_scan(self, request):
        data = await request.json()
        asyncio.create_task(self._run_scan(data))
        return web.json_response({"status": "started"})

    async def _api_scan_status(self, request):
        return web.json_response({"status": self.scan_status, "target": self.scan_target})

    async def _api_ai_analyze(self, request):
        asyncio.create_task(self._run_ai_analysis())
        return web.json_response({"status": "analyzing"})

    async def _api_results(self, request):
        # Serialize results (filter out non-serializable items)
        safe_results = {}
        for k, v in self.scan_results.items():
            if isinstance(v, list):
                safe_results[k] = v
        return web.json_response(safe_results, dumps=lambda x: json.dumps(x, default=str))

    def start(self, open_browser=True):
        """Start the dashboard server."""
        if open_browser:
            threading.Timer(1.5, lambda: webbrowser.open(f"http://{self.host}:{self.port}")).start()
        print(f"\n  [*] Dashboard running at http://{self.host}:{self.port}")
        print(f"  [*] Press Ctrl+C to stop\n")
        web.run_app(self.app, host=self.host, port=self.port, print=None)
