import tornado.web

from satellite.handlers.har_handler import HarFlows
from satellite.handlers.ws_event_handler import ClientConnection
from satellite.handlers.flow_handlers import Flows, Events, \
    FlowContentView, ReplayFlow, DuplicateFlow, ResumeFlows, \
    KillFlows, ResumeFlow, KillFlow, ClearAll, FlowHandler, Index
from satellite.handlers.route_handler import RoutesFlows, RouteFlows


class WebApplication(tornado.web.Application):

    def __init__(self,  master):
        super().__init__(debug=True)
        self.master = master
        self.add_handlers(r'^(localhost|[0-9.]+|\[[0-9a-fA-F:]+\])$', [
            (r"/", Index),
            (r"/updates", ClientConnection),
            (r"/route", RoutesFlows),
            (r"/route/(?P<route_id>[0-9a-f\-]+)", RouteFlows),
            (r"/flows(?:\.json)?", Flows),
            (r"/events(?:\.json)?", Events),
            # (r"/flows/dump", DumpFlows),
            (r"/flows/resume", ResumeFlows),
            (r"/flows/kill", KillFlows),
            (r"/flows/(?P<flow_id>[0-9a-f\-]+)", FlowHandler),
            (r"/flows/(?P<flow_id>[0-9a-f\-]+)/resume", ResumeFlow),
            (r"/flows/(?P<flow_id>[0-9a-f\-]+)/kill", KillFlow),
            (r"/flows/(?P<flow_id>[0-9a-f\-]+)/har", HarFlows),
            (r"/flows/(?P<flow_id>[0-9a-f\-]+)/replay", ReplayFlow),
            (r"/flows/(?P<flow_id>[0-9a-f\-]+)/duplicate", DuplicateFlow),
            (r"/clear", ClearAll),
            (r"/flows/(?P<flow_id>[0-9a-f\-]+)/(?P<message>request|response)/content/(?P<content_view>[0-9a-zA-Z\-\_]+)(?:\.json)?", FlowContentView)
        ])
