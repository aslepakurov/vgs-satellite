import React, { useEffect } from 'react';
import { connect } from 'react-redux';
import RoutesPage from './RoutesPage/RoutesPage';
import { fetchRoutes, deleteRoute } from 'src/redux/modules/routes';
import { IRoute } from 'src/redux/interfaces/routes';

const mapStateToProps = ({ routes }: any) => {
  return {
    routes: routes.list,
    isLoading: routes.isLoading,
  };
}


const mapDispatchToProps = {
  fetchRoutes,
  deleteRoute,
};

export interface IRoutesListContainerProps {
  routes: IRoute[];
  isLoading: boolean;
  fetchRoutes: () => void;
  deleteRoute: (routeId: string) => void;
}

const RoutesListContainer: React.FunctionComponent<IRoutesListContainerProps> = (props) => {
  const { routes, isLoading, fetchRoutes, deleteRoute } = props;

  useEffect(() => {
    fetchRoutes();
  }, [])

  return (
    <div>
      <RoutesPage
        isLoading={isLoading}
        routes={routes}
        deleteRoute={deleteRoute}
      />
    </div>
  );
};

export default connect(
  mapStateToProps,
  mapDispatchToProps,
)(RoutesListContainer);
