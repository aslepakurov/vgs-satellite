import React from 'react';
import { Route, Switch } from 'react-router-dom';
import PreCollectContainer from 'src/components/vault/PreCollect/PreCollectContainer';
import RoutesListContainer from 'src/components/vault/RoutesList/RoutesListContainer';

interface IAppSwitchProps {
}

const AppSwitch: React.FC<IAppSwitchProps> = (props) => {
  return (
    <Switch>
      <Route exact path="/" component={PreCollectContainer}/>
      <Route exact path="/routes" component={RoutesListContainer}/>
    </Switch>
  );
};

export default AppSwitch;
