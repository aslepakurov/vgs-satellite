import React from 'react';
import { withRouter } from 'react-router-dom';
import { IRoute } from 'src/redux/interfaces/routes';
import { Button, Icon, Popover } from 'src/components/antd';
import { getRouteProtocol, isInbound } from 'src/redux/utils/routes';
import Yaml from 'src/components/molecules/Yaml/Yaml';

export interface IRouteTitleProps {
  route: IRoute;
  deleteRoute: () => void;
}

export const RouteTitle = (props: IRouteTitleProps) => {
  const { route, deleteRoute } = props;
  const tags: Partial<typeof route.tags> = { ...route.tags };
  const routeProtocol = getRouteProtocol(route);
  const isRouteInbound = isInbound(route);
  const isSourceEndpoint = route.source_endpoint === '*' && !isRouteInbound && routeProtocol === 'routes';

  const content = (
    <>
      <p className="mb-0">This route allows requests from any IP address.</p>
      <p className="mb-0">You can restrict access to specific IP addresses.</p>
      <p className="mb-0">You will be allowed to edit and confirm the<br/>addresses before the change is made.</p>
    </>
  );

  return (
    <div className="row no-gutters justify-content-between">
      <div className="d-flex">
        {(isSourceEndpoint) &&
          <Icon
            type="warning"
            theme="filled"
            className="align-self-center mr-2 text-warning"
            style={{ fontSize: '18px' }}
          />
        }
        {tags.name
          ? <span className="align-self-center" data-role="route-item-name-value">{tags.name}</span>
          : isSourceEndpoint && <span className="align-self-center">Finish the route configuration</span>
        }
        {isSourceEndpoint &&
          <Popover
            content={content}
            trigger="hover"
          >
            <Icon
              type="question-circle"
              className="ml-2 align-self-center text-secondary"
              theme="filled"
              style={{ fontSize: '14px' }}
            />
          </Popover>
        }
      </div>

      <div className="d-flex">
        <Button type="link" className="px-0 mr-3" onClick={deleteRoute}>
          <Icon type="delete" />
          <span className="ml-1">Delete route</span>
        </Button>
        <Yaml route={route} />
      </div>
    </div>
  );
};

export default withRouter(RouteTitle);
