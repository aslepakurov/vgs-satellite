import React from 'react';
import classnames from 'classnames';
import FlowStatus from './FlowStatus';
import FlowDomain from './FlowDomain';
import FlowPath from './FlowPath';
import { ILog } from 'src/redux/interfaces/logs';
import { Table } from 'reactstrap';
import { formatDate, dateFromNow } from 'src/redux/utils/utils';

export interface IFlowsTableProps {
  logs: ILog[];
  onSelect: (log: ILog) => void;
}

const FlowsTable: React.SFC<IFlowsTableProps> = (props) => {
  const { logs, onSelect } = props;

  return (
    <div className="flow-logs mb-3">
      <Table striped className="flows-table" data-role="flows-table">
        <thead>
          <tr>
            <th className="flows-table_status">Status</th>
            <th className="flows-table_method">Method</th>
            <th>Domain</th>
            <th>Path</th>
            <th>Date</th>
          </tr>
        </thead>
        <tbody>
          {logs.map(log => (
            <tr
              key={log.id ?? `${log.startedDateTime}${log.time}`}
              className={classnames({
                '--isLoaded': log.isLoaded,
              })}
              data-role="logs-row"
            >
              <td className="flows-table_status-column" onClick={() => onSelect(log)}>
                <FlowStatus log={log} />
              </td>
              {log.http && !!log.http.method &&
                <td className="smallbold" onClick={() => onSelect(log)}>{log.http.method}</td>
              }
              <td onClick={() => onSelect(log)}>
                <FlowDomain log={log} />
              </td>
              <td onClick={() => onSelect(log)}>
                <FlowPath log={log} />
              </td>
              <td className="text-nowrap" onClick={() => onSelect(log)}>
                <span title={dateFromNow(log.occurred_at)}>
                  {formatDate(log.occurred_at)}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </Table>
    </div>
  );
};

export default FlowsTable;
