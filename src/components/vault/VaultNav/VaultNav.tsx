import React from 'react';
import { NavLink } from 'react-router-dom';

export interface IVaultNavProps {
}

export const VaultNav: React.FC<IVaultNavProps> = (props) => {

  return (
    <div className="navside-item-wrapper mt-3">
      <ul data-role="vault-menu">
        <NavLink
          exact
          className="menu-item"
          to="/"
        >
          Logs
        </NavLink>
        <NavLink
          className="menu-item"
          to="/routes"
        >
          Routes
        </NavLink>
      </ul>
    </div>

  );
};

export default VaultNav;
