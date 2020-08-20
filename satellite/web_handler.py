import tornado.web

from satellite.flow_handlers import Flows, HarFlows, ClientConnection, Events, \
    FlowContentView, ReplayFlow, DuplicateFlow, ResumeFlows, \
    KillFlows, ResumeFlow, KillFlow, ClearAll, FlowHandler


class WebApplication(tornado.web.Application):

    def __init__(self,  master):
        super().__init__(debug=True)
        self.master = master
        self.add_handlers(r'^(localhost|[0-9.]+|\[[0-9a-fA-F:]+\])$', [
            (r"/updates", ClientConnection),
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
