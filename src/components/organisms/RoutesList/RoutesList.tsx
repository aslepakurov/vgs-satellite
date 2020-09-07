import React from 'react';
import { IRoute } from 'src/redux/interfaces/routes';
import Route from './Route';

export interface IRoutesListProps {
  list: IRoute[];
  deleteRoute: (route: IRoute) => void;
}

const RoutesList: React.FC<IRoutesListProps> = (props) => {
  const { list, deleteRoute } = props;

  return (
    <div className="routes-list">
      {list.map(route => <div className="mb-4" key={route.id}>
        <Route route={route} deleteRoute={() => deleteRoute(route)} />
      </div>)}
    </div>
  );
};
export default RoutesList;
