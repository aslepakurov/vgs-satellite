import tornado.httpserver
import tornado.ioloop
from tornado.platform.asyncio import AsyncIOMainLoop

from mitmproxy import master
from mitmproxy import addons
from mitmproxy import optmanager
from mitmproxy.addons import view
from mitmproxy.addons import dumper
from mitmproxy.addons import intercept
from mitmproxy.addons import termlog
from mitmproxy.addons import termstatus
from mitmproxy.addons import eventstore
from mitmproxy.tools.web import static_viewer, webaddons
from mitmproxy.tools.web.app import ClientConnection as clientConnection
from mitmproxy.tools.web.app import logentry_to_json
from mitmproxy.log import LogEntry

from satellite.web_handler import WebApplication
from satellite.flow_handlers import flow_to_json


class ProxyMaster(master.Master):
    def __init__(self, options, with_termlog=True):
        super().__init__(options)
        self.view = view.View()
        self.events = eventstore.EventStore()
        self.addons.add(*addons.default_addons())
        self.addons.add(
            webaddons.WebAddon(),
            static_viewer.StaticViewer(),
            intercept.Intercept(),
            dumper.Dumper(),
            self.view
        )
        if with_termlog:
            self.addons.add(termlog.TermLog(), termstatus.TermStatus())
        self.app = WebApplication(self)

    def _sig_view_add(self, view, flow):
        clientConnection.broadcast(
            resource="flows",
            cmd="add",
            data=flow_to_json(flow)
        )

    def _sig_view_update(self, view, flow):
        clientConnection.broadcast(
            resource="flows",
            cmd="update",
            data=flow_to_json(flow)
        )

    def _sig_view_remove(self, view, flow, index):
        clientConnection.broadcast(
            resource="flows",
            cmd="remove",
            data=flow.id
        )

    def _sig_view_refresh(self, view):
        clientConnection.broadcast(
            resource="flows",
            cmd="reset"
        )

    def _sig_events_add(self, event_store, entry: LogEntry):
        clientConnection.broadcast(
            resource="events",
            cmd="add",
            data=logentry_to_json(entry)
        )

    def _sig_events_refresh(self, event_store):
        clientConnection.broadcast(
            resource="events",
            cmd="reset"
        )

    def _sig_options_update(self, options, updated):
        options_dict = optmanager.dump_dicts(options, updated)
        clientConnection.broadcast(
            resource="options",
            cmd="update",
            data=options_dict
        )

    def _sig_settings_update(self, options, updated):
        clientConnection.broadcast(
            resource="settings",
            cmd="update",
            data={k: getattr(options, k) for k in updated}
        )

    def run(self):  # pragma: no cover
        AsyncIOMainLoop().install()
        iol = tornado.ioloop.IOLoop.instance()
        http_server = tornado.httpserver.HTTPServer(self.app)
        http_server.listen(self.options.web_port, self.options.web_host)
        web_url = "http://{}:{}/".format(self.options.web_host, self.options.web_port)
        self.log.info(
            "Web server listening at {}".format(web_url),
        )
        self.run_loop(iol.start)
