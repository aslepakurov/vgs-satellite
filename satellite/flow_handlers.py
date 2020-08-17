import json
import base64
from datetime import datetime
from datetime import timezone
from typing import Dict, Set, Optional

import tornado.escape

import mitmproxy.flow
import mitmproxy.tools.web.master
from mitmproxy import http
from mitmproxy import version
from mitmproxy import connections
from mitmproxy import ctx
from mitmproxy.utils import strutils
from mitmproxy.net.http import cookies
from mitmproxy.tools.web.app import RequestHandler

SERVERS_SEEN: Set[connections.ServerConnection] = set()


class Flows(RequestHandler):

    def get(self):
        self.write([flow_to_json(f) for f in self.view])


class HarFlows(RequestHandler):

    def get(self, flow_id):
        flow = self.flow

        HAR: Dict = {}

        HAR.update({
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "VGS Satellite HAR dump",
                    "version": "0.1",
                    "comment": "mitmproxy version %s" % version.MITMPROXY
                },
                "entries": []
            }
        })

        """
           Called when a server response has been received.
        """

        # -1 indicates that these values do not apply to current request
        ssl_time = -1
        connect_time = -1

        if flow.server_conn and flow.server_conn not in SERVERS_SEEN:
            connect_time = (flow.server_conn.timestamp_tcp_setup -
                            flow.server_conn.timestamp_start)

            if flow.server_conn.timestamp_tls_setup is not None:
                ssl_time = (flow.server_conn.timestamp_tls_setup -
                            flow.server_conn.timestamp_tcp_setup)

            SERVERS_SEEN.add(flow.server_conn)

        # Calculate raw timings from timestamps. DNS timings can not be calculated
        # for lack of a way to measure it. The same goes for HAR blocked.
        # mitmproxy will open a server connection as soon as it receives the host
        # and port from the client connection. So, the time spent waiting is actually
        # spent waiting between request.timestamp_end and response.timestamp_start
        # thus it correlates to HAR wait instead.
        timings_raw = {
            'send': flow.request.timestamp_end - flow.request.timestamp_start,
            'receive': flow.response.timestamp_end - flow.response.timestamp_start,
            'wait': flow.response.timestamp_start - flow.request.timestamp_end,
            'connect': connect_time,
            'ssl': ssl_time,
        }

        # HAR timings are integers in ms, so we re-encode the raw timings to that format.
        timings = {
            k: int(1000 * v) if v != -1 else -1
            for k, v in timings_raw.items()
        }

        # full_time is the sum of all timings.
        # Timings set to -1 will be ignored as per spec.
        full_time = sum(v for v in timings.values() if v > -1)

        started_date_time = datetime.fromtimestamp(flow.request.timestamp_start, timezone.utc).isoformat()

        # Response body size and encoding
        response_body_size = len(flow.response.raw_content) if flow.response.raw_content else 0
        response_body_decoded_size = len(flow.response.content) if flow.response.content else 0
        response_body_compression = response_body_decoded_size - response_body_size

        entry = {
            "startedDateTime": started_date_time,
            "time": full_time,
            "request": {
                "method": flow.request.method,
                "url": flow.request.url,
                "httpVersion": flow.request.http_version,
                "cookies": format_request_cookies(flow.request.cookies.fields),
                "headers": name_value(flow.request.headers),
                "queryString": name_value(flow.request.query or {}),
                "headersSize": len(str(flow.request.headers)),
                "bodySize": len(flow.request.content),
            },
            "response": {
                "status": flow.response.status_code,
                "statusText": flow.response.reason,
                "httpVersion": flow.response.http_version,
                "cookies": format_response_cookies(flow.response.cookies.fields),
                "headers": name_value(flow.response.headers),
                "content": {
                    "size": response_body_size,
                    "compression": response_body_compression,
                    "mimeType": flow.response.headers.get('Content-Type', '')
                },
                "redirectURL": flow.response.headers.get('Location', ''),
                "headersSize": len(str(flow.response.headers)),
                "bodySize": response_body_size,
            },
            "cache": {},
            "timings": timings,
        }

        # Store binary data as base64
        if strutils.is_mostly_bin(flow.response.content):
            entry["response"]["content"]["text"] = base64.b64encode(flow.response.content).decode()
            entry["response"]["content"]["encoding"] = "base64"
        else:
            entry["response"]["content"]["text"] = flow.response.get_text(strict=False)

        if flow.request.method in ["POST", "PUT", "PATCH"]:
            params = [
                {"name": a, "value": b}
                for a, b in flow.request.urlencoded_form.items(multi=True)
            ]
            entry["request"]["postData"] = {
                "mimeType": flow.request.headers.get("Content-Type", ""),
                "text": flow.request.get_text(strict=False),
                "params": params
            }

        entry["serverIPAddress"] = str(flow.server_conn.ip_address[0])

        HAR["log"]["entries"].append(entry)

        json_dump: str = json.dumps(HAR, indent=2)
        ctx.log(json_dump)

        # raw
        ctx.log("HAR dump finished (wrote %s bytes to file)" % len(json_dump))
        self.write([HAR])


def format_cookies(cookie_list):
    rv = []

    for name, value, attrs in cookie_list:
        cookie_har = {
            "name": name,
            "value": value,
        }

        # HAR only needs some attributes
        for key in ["path", "domain", "comment"]:
            if key in attrs:
                cookie_har[key] = attrs[key]

        # These keys need to be boolean!
        for key in ["httpOnly", "secure"]:
            cookie_har[key] = bool(key in attrs)

        # Expiration time needs to be formatted
        expire_ts = cookies.get_expiration_ts(attrs)
        if expire_ts is not None:
            cookie_har["expires"] = datetime.fromtimestamp(expire_ts, timezone.utc).isoformat()

        rv.append(cookie_har)

    return rv


def format_request_cookies(fields):
    return format_cookies(cookies.group_cookies(fields))


def format_response_cookies(fields):
    return format_cookies((c[0], c[1][0], c[1][1]) for c in fields)


def name_value(obj):
    """
        Convert (key, value) pairs to HAR format.
    """
    return [{"name": k, "value": v} for k, v in obj.items()]


def flow_to_json(flow: mitmproxy.flow.Flow) -> dict:
    """
    Remove flow message content and cert to save transmission space.

    Args:
        flow: The original flow.
    """
    f = {
        "id": flow.id,
        "intercepted": flow.intercepted,
        "client_conn": flow.client_conn.get_state(),
        "server_conn": flow.server_conn.get_state(),
        "type": flow.type,
        "modified": flow.modified(),
        "marked": flow.marked,
    }
    # .alpn_proto_negotiated is bytes, we need to decode that.
    for conn in "client_conn", "server_conn":
        if f[conn]["alpn_proto_negotiated"] is None:
            continue
        f[conn]["alpn_proto_negotiated"] = \
            f[conn]["alpn_proto_negotiated"].decode(errors="backslashreplace")
    # There are some bytes in here as well, let's skip it until we have them in the UI.
    f["client_conn"].pop("tls_extensions", None)
    if flow.error:
        f["error"] = flow.error.get_state()

    if isinstance(flow, http.HTTPFlow):
        content_length: Optional[int]
        content: Optional[str]
        if flow.request:
            content_length = None
            content = None
            if flow.request.raw_content:
                try:
                    content = flow.request.raw_content.decode("utf-8")
                    content_length = len(flow.request.raw_content)
                except UnicodeDecodeError:
                    ctx.log(f"Unsupported request content format for request: {flow.id}")
            f["request"] = {
                "method": flow.request.method,
                "scheme": flow.request.scheme,
                "host": flow.request.host,
                "port": flow.request.port,
                "path": flow.request.path,
                "http_version": flow.request.http_version,
                "headers": tuple(flow.request.headers.items(True)),
                "contentLength": content_length,
                "content": content,
                "timestamp_start": flow.request.timestamp_start,
                "timestamp_end": flow.request.timestamp_end,
                "is_replay": flow.request.is_replay,
                "pretty_host": flow.request.pretty_host,
            }
        if flow.response:
            content_length = None
            content = None
            if flow.response.raw_content:
                try:
                    content = flow.response.raw_content.decode("utf-8")
                    content_length = len(flow.response.raw_content)
                except UnicodeDecodeError:
                    ctx.log(f"Unsupported response content format for request: {flow.id}")
            f["response"] = {
                "http_version": flow.response.http_version,
                "status_code": flow.response.status_code,
                "reason": flow.response.reason,
                "headers": tuple(flow.response.headers.items(True)),
                "contentLength": content_length,
                "content": content,
                "timestamp_start": flow.response.timestamp_start,
                "timestamp_end": flow.response.timestamp_end,
                "is_replay": flow.response.is_replay,
            }
            if flow.response.data.trailers:
                f["response"]["trailers"] = tuple(flow.response.data.trailers.items(True))

    f.get("server_conn", {}).pop("cert", None)
    f.get("client_conn", {}).pop("mitmcert", None)

    return f
