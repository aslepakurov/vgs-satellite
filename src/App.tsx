import React from 'react';
import { withRouter } from 'react-router-dom';
import NavBar from 'src/components/organization/header/NavBar';
import AppSwitch from './AppSwitch';
import VaultSidebar from 'src/components/vault/VaultSidebar';

const App: React.FunctionComponent = () => {
  return (
    <div>
      <div className="navbar-wrapper navbar-simple">
        <NavBar />
      </div>
      <div className="main-menu-content mb-3 mt-5">
        <VaultSidebar />
        <div className="app-content d-flex">
          <div id="vault-content" className="container-fluid mt-5">
            <AppSwitch />
          </div>
        </div>
      </div>
    </div>
  );
};

export default withRouter(App);