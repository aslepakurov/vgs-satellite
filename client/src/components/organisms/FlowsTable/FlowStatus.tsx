import * as React from 'react';
import { Badge } from 'reactstrap';
import { badgeColor } from 'src/redux/utils/utils';
import { ILog } from 'src/redux/interfaces/logs';

interface IFlowStatusProps {
  log: ILog;
}

const FlowStatus: React.FunctionComponent<IFlowStatusProps> = (props) => {
  const { log } = props;

  const status =
    log.upstream_status || log.proxy_status || log.response?.status_code;

  if (!status) return <></>;

  return <Badge color={badgeColor(status)}>{status}</Badge>;
};

export default FlowStatus;
