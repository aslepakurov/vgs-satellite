import * as React from 'react';
import StringWrapper from 'src/components/atoms/StringWrapper/StringWrapper';
import { ILog } from 'src/redux/interfaces/logs';

interface IFlowPathProps {
  log: ILog;
}

const FlowPath: React.FunctionComponent<IFlowPathProps> = (props) => {
  const { log } = props;

  const urlRegex = RegExp('^(https?:)//(([^:/?#]*)(?::([0-9]+))?)');
  const isUrlValid = (url: string) => !!url && urlRegex.test(url);
  const splitUrl = (url: string) => isUrlValid(url) && url.match(urlRegex);
  const getPathname = (url: string) => url.split(splitUrl(url)[0])[1];

  if (isUrlValid(log.path)) {
    return (
      <div className='text-nowrap fixed-table'>
        <StringWrapper cutMiddle size={50} id={`path-${log.id}`}>
          {getPathname(log.path)}
        </StringWrapper>
      </div>
    );
  }

  return (
    <div className='text-nowrap fixed-table'>
      <StringWrapper cutMiddle size={50} id={`path-${log.id}`}>
        {log.path?.startsWith('/') ? log.path : log.request?.path}
      </StringWrapper>
    </div>
  );
};

export default FlowPath;
