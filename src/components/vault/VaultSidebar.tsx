import React from 'react';
import { Link, withRouter } from 'react-router-dom';
import VaultNav from './VaultNav/VaultNav';

export interface IVaultSidebarProps {
  location: any;
}

const RELEASE_VERSION = process.env.RELEASE_VERSION;

export const VaultSidebar: React.SFC<IVaultSidebarProps> = (props) => {
  return (
    <div className="navside" id="vault-navside">
      <VaultNav />
      <div className="navside-logo">
        <div className="navbar-header">
          <Link
            to={'/'}
            className="navbar-brand"
            title={RELEASE_VERSION}
          >
            <img src="/images/vgs-dashboard-logo.svg" />
          </Link>
        </div>
      </div>
    </div>
  );
};

export default withRouter(VaultSidebar);
