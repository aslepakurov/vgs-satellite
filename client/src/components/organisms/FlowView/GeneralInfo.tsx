import * as React from 'react';
import RouteTypeLabel from 'src/components/organisms/FlowsTable/RouteTypeLabel';
import { ILog } from 'src/redux/interfaces/logs';
import { Badge, Table } from 'reactstrap';
import { badgeColor, getQueryParameters } from 'src/redux/utils/utils';
import DiffSnippet from 'src/components/atoms/DiffSnippet/DiffSnippet';
import _ from 'lodash';
import { Icon, Popover } from 'src/components/antd';

interface IGeneralInfoProps {
  log: ILog;
  validUri: string;
  showRequestMethod: boolean;
  showRouteType: boolean;
  showStatusCode: boolean;
}

const GeneralInfo: React.SFC<IGeneralInfoProps> = (
  { log, validUri, showRequestMethod, showRouteType, showStatusCode }) => {
  const { route_type, upstream_time_ms, upstream_status, proxy_status, http } = log;

  return (
    <Table className="general-table pb-3">
      <tbody>
        {!!route_type && (
          <tr>
            <td className="smallbold w-25">Type</td>
              <td>
                {showRouteType
                  ? <RouteTypeLabel type={route_type} />
                  : route_type
                }
              </td>
          </tr>
        )}
        {log.flow && log.flow.request && !!log.flow.request.httpVersion && (
          <tr>
            <td className="smallbold">Protocol</td>
            <td>{log.flow.request.httpVersion}</td>
          </tr>
        )}
        {!!validUri && (
          <tr>
            <td className="smallbold">URL</td>
            <td>
              {validUri}
            </td>
          </tr>
        )}
        { log.flow && log.flow.REQUEST_REWRITTEN && !!log.flow.REQUEST_REWRITTEN.url &&
        !_.isEqual(getQueryParameters(log.flow.request.url), getQueryParameters(log.flow.REQUEST_REWRITTEN.url)) ?
          <tr className="uri-diff">
            <td className="smallbold">Query Parameters</td>
            <DiffSnippet
              oldCode={getQueryParameters(log.flow.request.url)}
              newCode={getQueryParameters(log.flow.REQUEST_REWRITTEN.url)}
              splitView={false}
              hideLineNumbers={true}
            />
          </tr>
          :
          log.flow && log.flow.request && !!log.flow.request.url &&
          getQueryParameters(log.flow.request.url) &&
            <tr>
              <td className="smallbold">Query Parameters</td>
              <td>{getQueryParameters(log.flow.request.url)}</td>
            </tr>
        }
        {showRequestMethod && !!http.method &&
          <tr>
            <td className="smallbold">Request Method</td>
            <td>
              <span className="d-flex text-left align-items-center">
                {http.method}
                {log?.request?.is_replay && (
                  <Popover
                    trigger="hover"
                    content={
                      <span className="text-sm d-inline-block">
                        Replayed request
                      </span>
                    }
                  >
                    <Icon type="reload" className="ml-2 text-success" />
                  </Popover>
                )}
              </span>
            </td>
          </tr>
        }
        {showStatusCode && !!upstream_status &&
          <tr>
            <td className="smallbold">Upstream Status Code</td>
            <td>
              <Badge color={badgeColor(upstream_status)}>
                {upstream_status}
              </Badge>
            </td>
          </tr>
        }
        {!!proxy_status && upstream_status !== proxy_status && (
          <tr>
            <td className="smallbold">Status Code</td>
            <td>
              <Badge color={badgeColor(proxy_status)}>
                {proxy_status}
              </Badge>
            </td>
          </tr>
        )}
        {!!upstream_time_ms && (
          <tr>
            <td className="smallbold">Upstream Latency</td>
            <td>{upstream_time_ms} ms</td>
          </tr>
        )}
      </tbody>
    </Table>
  );
};

export default GeneralInfo;
