import logging
from functools import singledispatchmethod
from typing import Any, List, Optional

from mitmproxy.http import HTTPFlow

from . import commands
from . import exceptions
from ..flows import copy_flow, get_flow_state


logger = logging.getLogger()


class ProxyCommandProcessor:
    def __init__(self, proxy_process):
        self._proxy_process = proxy_process

    @property
    def master(self):
        return self._proxy_process.master

    @property
    def view(self):
        return self.master.view

    @singledispatchmethod
    def process_command(self, cmd) -> Any:
        raise NotImplementedError(f'Unknown command: {cmd}.')

    @process_command.register
    def _(self, _: commands.StopCommand):
        self._proxy_process.stop()

    @process_command.register
    def _(self, _: commands.GetFlowsCommand) -> List[dict]:
        return list(map(get_flow_state, self.view))

    @process_command.register
    def _(self, cmd: commands.GetFlowCommand) -> Optional[dict]:
        flow = self._get_flow(cmd.flow_id)
        return get_flow_state(flow)

    @process_command.register
    def _(self, cmd: commands.RemoveFlowCommand) -> Optional[str]:
        flow = self._get_flow(cmd.flow_id)
        self.view.remove([flow])

    @process_command.register
    def _(self, cmd: commands.DuplicateFlowCommand) -> Optional[str]:
        flow = self._get_flow(cmd.flow_id)
        new_flow = copy_flow(flow)
        self.view.add([new_flow])
        return new_flow.id

    @process_command.register
    def _(self, cmd: commands.ReplayFlowCommand):
        flow = self._get_flow(cmd.flow_id)
        if hasattr(flow, 'request_raw'):
            flow.request = flow.request_raw

        # Workaround for https://github.com/mitmproxy/mitmproxy/issues/4318
        if (
            flow.request.http_version == 'HTTP/2.0' and
            ':authority' not in flow.request.headers
        ):
            flow.request.headers[':authority'] = flow.request.authority

        self.master.commands.call('replay.client', [flow])

    @process_command.register
    def _(self, cmd: commands.UpdateFlowCommand):
        flow = self._get_flow(cmd.flow_id)
        flow.backup()
        try:
            for a, b in cmd.flow_data.items():
                if a == 'request' and hasattr(flow, 'request_raw'):
                    request = flow.request_raw
                    for k, v in b.items():
                        if k in ['method', 'scheme', 'host', 'path', 'http_version']:
                            setattr(request, k, str(v))
                        elif k == 'port':
                            request.port = int(v)
                        elif k == 'headers':
                            request.headers.clear()
                            for header in v:
                                request.headers.add(*header)
                        elif k == 'content':
                            request.text = v
                        else:
                            raise exceptions.FlowUpdateError('Unknown request field.')

                elif a == 'response' and hasattr(flow, 'response_raw'):
                    response = flow.response_raw
                    for k, v in b.items():
                        if k in ['msg', 'http_version']:
                            setattr(response, k, str(v))
                        elif k == 'code':
                            response.status_code = int(v)
                        elif k == 'headers':
                            response.headers.clear()
                            for header in v:
                                response.headers.add(*header)
                        elif k == 'content':
                            response.text = v
                        else:
                            raise exceptions.FlowUpdateError('Unknown response field.')
                else:
                    raise exceptions.FlowUpdateError('Unknown flow field.')

        except Exception as exc:
            logger.error(f'Unable to update flow {flow.id}: {exc}')
            flow.revert()
            raise

        self.view.update([flow])

    def _get_flow(self, flow_id: str) -> HTTPFlow:
        flow = self.view.get_by_id(flow_id)
        if not flow:
            raise exceptions.UnexistentFlowError(flow_id)
        return flow
