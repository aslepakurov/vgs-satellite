import React from 'react';
import Card from 'src/components/atoms/Card/react-card';
import { IRoute } from 'src/redux/interfaces/routes';
import { getUpstream, isInbound } from 'src/redux/utils/routes';
import RouteTitle from './RouteTitle';
import RouteFooter from './RouteFooter';

export interface IRouteProps {
  route: IRoute;
  deleteRoute: (route: IRoute) => void;
}

export const Route: React.FC<IRouteProps> = (props) => {
  const { route, deleteRoute } = props;

  const title = (
    <RouteTitle
      route={route}
      deleteRoute={deleteRoute}
    />
  );
  const footer = <RouteFooter route={route} />;
  const isRouteInbound = isInbound(route);
  const warningConditions = [
    props.route.source_endpoint === '*' && !isRouteInbound,
  ];
  const warningBackground = warningConditions.some(Boolean) ? 'warning-background' : '';

  return (
    <div className="route-item" data-role="route-item">
      <Card title={title} footer={footer} headerColor={warningBackground}>
        <div data-role="route-item-card-container">
          <div className="d-flex justify-content-between">
            <div className="w-50">
              <p className="filter-title route-item__key">Upstream</p>
              <div className="route-item__value --upstream" data-role="route-item-host-value">
                {getUpstream(route)}
              </div>
            </div>
            <div>
              <p className="filter-title route-item__key">Route ID</p>
              <div className="route-item__value" data-role="route-item-id-value">{route.id}</div>
            </div>
            <div>
              <p className="filter-title route-item__key">Updated</p>
              <div className="route-item__value">{route.updated_at || route.created_at}</div>
            </div>
          </div>
        </div>
      </Card>
    </div>
  );
};

export default Route;
