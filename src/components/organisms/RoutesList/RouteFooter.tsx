import React from 'react';
import Icon from 'src/components/atoms/Icon/Icon';
import { IRoute } from 'src/redux/interfaces/routes';
import { UncontrolledCollapse } from 'reactstrap';
import _ from 'lodash';
import RouteEntryInfo from 'src/components/organisms/RouteEntry/RouteEntryInfo';

export interface IRouteFooterProps {
  route: IRoute;
}

export const RouteFooter = (props: IRouteFooterProps) => {
  const { route } = props;
  const routeId = _.uniqueId('route-');

  return (
    <>
      {route.entries.length ?
        <>
          <div className="row no-gutters justify-content-between filter-toggler" id={routeId}>
            <span className="align-middle">
              <Icon type="accent" name="check" position="left" />
              Filters
            </span>
            <Icon type="primary-light" name="chevron-down"/>
          </div>
          <UncontrolledCollapse toggler={routeId}>
            <RouteEntryInfo route={route} />
          </UncontrolledCollapse>
        </>
        :
        <div className="row no-gutters">
          <span className="align-middle">
            <Icon type="danger" name="exclamation-circle" position="left" />
            No Filters
          </span>
        </div>
      }
    </>
  );
};

export default RouteFooter;
