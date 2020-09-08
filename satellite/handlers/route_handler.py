import tornado.escape

from satellite.handlers.flow_handlers import BaseHandler
from satellite.handlers import route_manager


class RoutesFlows(BaseHandler):

    def get(self):
        self.set_json_headers()
        routes = route_manager.get_all()
        self.write(routes)

    def post(self):
        data = tornado.escape.json_decode(self.request.body)
        route = data['data']['attributes']
        route_entity = route_manager.create(route)
        self.write(route_entity)


class RouteFlows(BaseHandler):

    def get(self, route_id):
        self.set_json_headers()
        route = route_manager.get(route_id)
        self.write(route)

    def put(self, route_id):
        data = tornado.escape.json_decode(self.request.body)
        route = data['data']['attributes']
        route_entity = route_manager.update(route_id, route)
        self.write(route_entity)

    def delete(self, route_id):
        route_manager.delete(route_id)
        self.write('OK')
