from mitmproxy import ctx


class VaultFlows:

    def __init__(self):
        pass

    def load(self, loader):
        ctx.log("Testing VAULT")

    def request(self, flow):
        self.process_flow(flow)

    def response(self, flow):
        self.process_flow(flow)

    def process_flow(self, flow):
        ctx.log("VAULT REQUSTS = " + str(flow))
