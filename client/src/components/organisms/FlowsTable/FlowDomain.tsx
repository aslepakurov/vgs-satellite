import * as React from 'react';
import StringWrapper from 'src/components/atoms/StringWrapper/StringWrapper';
import { constructUriFromLog } from 'src/redux/utils/utils';
import { ILog } from 'src/redux/interfaces/logs';

interface IFlowDomainProps {
  log: ILog;
}

const FlowDomain: React.FunctionComponent<IFlowDomainProps> = (props) => {
  const { log } = props;

  const urlRegex = RegExp('^(https?:)//(([^:/?#]*)(?::([0-9]+))?)');
  const isUrlValid = (url: string) => !!url && urlRegex.test(url);
  const splitUrl = (url: string) => isUrlValid(url) && url.match(urlRegex);
  const getDomain = (url: string) => splitUrl(url)[3];

  if (isUrlValid(log.path)) {
    return (
      <div className='text-nowrap'>
        <StringWrapper
          showAlways
          size={35}
          id={`domain-${log.id}`}
          tooltipText={log.path}
        >
          {getDomain(log.path)}
        </StringWrapper>
      </div>
    );
  }

  return (
    <div className='text-nowrap'>
      <StringWrapper
        showAlways
        size={35}
        id={`domain-${log.id}`}
        tooltipText={constructUriFromLog(log)}
      >
        {log?.upstream?.split(/:\d+$/)[0] || log.request.host}
      </StringWrapper>
    </div>
  );
};

export default FlowDomain;
