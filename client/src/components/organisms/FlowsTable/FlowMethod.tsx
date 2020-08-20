import * as React from 'react';
import { Icon, Popover } from 'src/components/antd';
import { ILog } from 'src/redux/interfaces/logs';

interface IFlowMethodProps {
  log: ILog;
}

const FlowMethod: React.FunctionComponent<IFlowMethodProps> = (props) => {
  const { log } = props;

  return (
    <span className='d-flex text-left align-items-center'>
      {log?.http?.method || ''}
      {log?.request?.is_replay && (
        <Popover
          trigger='hover'
          content={
            <span className='text-sm d-inline-block'>Replayed request</span>
          }
        >
          <Icon type='reload' className='ml-1 text-success' />
        </Popover>
      )}
    </span>
  );
};

export default FlowMethod;
