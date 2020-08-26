import tornado.escape

from satellite.handlers.flow_handlers import BaseHandler
from satellite.model.route import RouteManager


route_manager = RouteManager()


class RoutesFlows(BaseHandler):

    def get(self):
        self.set_json_headers()
        routes = route_manager.get_all()
        self.write([route.serialize for route in routes])

    def post(self):
        data = tornado.escape.json_decode(self.request.body)


class RouteFlows(BaseHandler):

    def get(self, route_id):
        self.set_json_headers()
        route = route_manager.get(route_id)
        self.write(route.serialize)

    def put(self, route_id):
        pass

    def delete(self, route_id):
        route_manager.delete(route_id)
