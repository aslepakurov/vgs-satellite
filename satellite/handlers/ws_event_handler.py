from typing import ClassVar

from mitmproxy.tools.web.app import WebSocketEventBroadcaster, logentry_to_json

from satellite.handlers.flow_handlers import flow_to_json


class ClientConnection(WebSocketEventBroadcaster):
    connections: ClassVar[set] = set()

    def check_origin(self, origin: str):
        return True
