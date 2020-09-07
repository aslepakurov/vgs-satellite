import React from 'react';
import RouteEntrySummary from 'src/components/organisms/RouteEntry/RouteEntrySummary';
import { IEntry } from 'src/redux/interfaces/routes';

export interface IRoutesListProps {
  entries: IEntry[];
}

const RouteSummary: React.SFC<IRoutesListProps> = ({ entries }) => {

  return (
    <>
      {entries.map(entry => (
        <div key={entry.id} className="row w-100 mx-0">
          <div className="col-12">
            <div className="row">
              <RouteEntrySummary entry={entry} />
            </div>
          </div>
        </div>
      ))}
    </>
  );
};

export default RouteSummary;
