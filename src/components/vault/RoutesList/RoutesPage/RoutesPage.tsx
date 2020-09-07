import _ from 'lodash';
import React, { useState } from 'react';
import RoutesList from 'src/components/organisms/RoutesList/RoutesList';
import RoutesListEmpty from 'src/components/organisms/RoutesList/RoutesListEmpty';
import RouteDeleteConfirmModal from 'src/components/organisms/RouteDeleteConfirmModal/RouteDeleteConfirmModal';
import { IRoute, TRouteType } from 'src/redux/interfaces/routes';
import { getProxyType } from 'src/redux/utils/routes';
import {
  TabContent,
  TabPane,
} from 'reactstrap';
import {Radio } from 'src/components/antd';

export interface IRoutesPageProps {
  routes: IRoute[];
  isLoading: boolean;
  deleteRoute: (routeId: string) => void;
}

function groupRoutes(list: IRoute[]): {Forward: IRoute[], Reverse: IRoute[]} {
  return _.groupBy(list, route => getProxyType(route));
}

const RoutesPage: React.SFC<IRoutesPageProps> = (props) => {
  const grouppedRoutes = groupRoutes(props.routes);
  const [activeTab, setActiveTab] = useState('all-routes');
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [currentRoute, setCurrentRoute] = useState<IRoute | undefined>();

  const handleDeleteRoute = (route: IRoute) => {
    setCurrentRoute(route);
    setIsDeleteModalOpen(true);
  }

  const handleDeleteRouteById = (routeId: string) => {
    props.deleteRoute(routeId);
    setIsDeleteModalOpen(false);
    setCurrentRoute(undefined);
  }

  function renderList(list: IRoute[], routeType: TRouteType) {
    return list ? (
      <div data-role={`routes-list-${routeType.toLowerCase()}`}>
        <RoutesList list={list} deleteRoute={(route: IRoute) => handleDeleteRoute(route)} />
      </div>)
      :
      <p className="text-center no-routes-message pt-4 pb-4">No {routeType} routes!</p>;
  }

  return (
    <div data-role="routes-container">
      {
        props.isLoading
        ? <div>Loading...</div>
        : (props.routes && props.routes.length)
          ? <div>
              <div className="row justify-content-end">
                <div className="col-4 d-flex justify-content-center align-self-center">
                  <Radio.Group value={activeTab} onChange={e => setActiveTab(e.target.value)}>
                    <Radio.Button value="all-routes">All</Radio.Button>
                    <Radio.Button value="inbound">Inbound</Radio.Button>
                    <Radio.Button value="outbound">Outbound</Radio.Button>
                  </Radio.Group>
                </div>
              </div>
              <TabContent className="mt-4" activeTab={activeTab}>
                <TabPane tabId="all-routes">
                  <h4>Inbound</h4>
                  {renderList(grouppedRoutes.Reverse, 'Inbound')}
                  <h4>Outbound</h4>
                  {renderList(grouppedRoutes.Forward, 'Outbound')}
                </TabPane>
                <TabPane tabId="inbound">
                  {renderList(grouppedRoutes.Reverse, 'Inbound')}
                </TabPane>
                <TabPane tabId="outbound">
                  {renderList(grouppedRoutes.Forward, 'Outbound')}
                </TabPane>
              </TabContent>
            </div>
          : <RoutesListEmpty />
      }
      {!!currentRoute && (
        <RouteDeleteConfirmModal
          isLoading={false}
          isModalOpen={isDeleteModalOpen}
          toggleModal={(isOpen: boolean) => setIsDeleteModalOpen(isOpen)}
          routeDeleteHandler={handleDeleteRouteById}
          route={currentRoute}
        />
      )}
    </div>
  );
};

export default RoutesPage;
