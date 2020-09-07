import React, { useEffect, useState } from 'react';
import { bindActionCreators, compose } from 'redux';
import { connect } from 'react-redux';
import UploadButton from 'src/components/atoms/UploadButton/UploadButton';
import FlowsTable from 'src/components/organisms/FlowsTable/FlowsTable';
import FlowView from 'src/components/organisms/FlowView/FlowView';
import QuickIntegrationModal from 'src/components/organisms/QuickIntegration/QuickIntegrationModal';
import Yaml from 'src/components/molecules/Yaml/Yaml';
import { entryToLog, entryToFlow } from 'src/redux/utils/preCollect';
import {
  addPrecollectLogs,
  triggerYamlModal,
  fetchFlows,
  replayRequest,
  duplicateRequest,
  deleteRequest,
} from 'src/redux/modules/preCollect';
import { saveRoute } from 'src/redux/modules/routes';
import { constructUriFromLog } from 'src/redux/utils/utils';
import { IRoute } from 'src/redux/interfaces/routes';

function mapStateToProps({ preCollect, routes }: any) {
  return {
    logs: preCollect.list,
    preRoute: preCollect.route,
    preRoutes: preCollect.routes,
    isYamlModalOpen: preCollect.isYamlModalOpen,
    isUploaded: preCollect.isUploaded,
    isSavingRoute: routes.isSaveInProgress,
  };
}

const mapDispatchToProps = (dispatch: any) => {
  return bindActionCreators(
    {
      addPrecollectLogs,
      triggerYamlModal,
      fetchFlows,
      replayRequest,
      duplicateRequest,
      deleteRequest,
      saveRoute,
    },
    dispatch,
  );
};

export interface IPreCollectContainerProps {
  routeType: 'inbound' | 'outbound';
  logs: any[];
  addPrecollectLogs: (logs: any[]) => void;
  fetchFlows: () => void;
  preRoutes: IRoute[];
  triggerYamlModal: any;
  isYamlModalOpen: boolean;
  isUploaded: boolean;
  isSavingRoute: boolean;
  replayRequest: (logId: string) => void;
  duplicateRequest: (logId: string) => void;
  deleteRequest: (logId: string) => void;
  saveRoute: (route: IRoute) => void;
}

export const PreCollectContainer: React.FunctionComponent<IPreCollectContainerProps> = (props) => {
  const {
    routeType,
    logs,
    preRoutes,
    triggerYamlModal,
    isYamlModalOpen,
    isUploaded,
    isSavingRoute,
    replayRequest,
    duplicateRequest,
    deleteRequest,
    saveRoute,
  } = props;

  const [selectedLog, selectLog] = useState(null);
  const [isSecurePayload, securePayload] = useState(false);
  const [preRouteType, setPreRouteType] = useState<'inbound'|'outbound'>('inbound');

  const onUpload = (har) => {
    const harParsed = JSON.parse(har);

    props.addPrecollectLogs(harParsed.log.entries);
  };

  useEffect(() => {
    if (isYamlModalOpen || selectedLog || isSecurePayload || isUploaded) {
      return;
    };
    props.fetchFlows();
  }, [isYamlModalOpen, selectedLog, isSecurePayload, isUploaded]);

  const handleOnRuleCreate = (selectedPhase: 'REQUEST' | 'RESPONSE') => {
    selectLog(null);
    securePayload(entryToFlow(selectedLog, selectedPhase));
  };

  const handleReplay = () => {
    replayRequest(selectedLog.id);
    selectLog(null);
  }
  const handleDuplicate = () => {
    duplicateRequest(selectedLog.id);
    selectLog(null);
  }
  const handleDelete = () => {
    deleteRequest(selectedLog.id);
    selectLog(null);
  };

  const handleSaveRoute = (route: IRoute) => {
    saveRoute(route);
  }

  return (
    <div className="container">
      <UploadButton onUpload={data => onUpload(data)} />
      {isSecurePayload && (
        <QuickIntegrationModal
          isReverse={preRouteType === 'inbound'}
          log={isSecurePayload}
          url={constructUriFromLog(isSecurePayload)}
          closeModal={() => securePayload(false)}
        />
      )}

      {selectedLog ? (
        <FlowView
          log={entryToFlow(selectedLog)}
          logFilters={{}}
          showSpinner={false}
          routes={null}
          onClose={() => selectLog(null)}
          onRuleCreate={(selectedPhase: string) => handleOnRuleCreate(selectedPhase)}
          setPreRouteType={type => setPreRouteType(type)}
          onReplay={handleReplay}
          onDuplicate={handleDuplicate}
          onDelete={handleDelete}
        />
      ) : null}

      {!!logs.length && (
        <FlowsTable
          onSelect={selectLog}
          logs={logs.map(entry => entryToLog(entry, routeType))}
        />
      )}
      <Yaml
        routes={preRoutes}
        isExternal={true}
        setExternalToggle={() => triggerYamlModal(!isYamlModalOpen)}
        isExternalOpen={isYamlModalOpen}
        handleSaveRoute={handleSaveRoute}
        isSavingRoute={isSavingRoute}
      />
    </div>
  );
};

export default compose(
  connect(
    mapStateToProps,
    mapDispatchToProps,
  ),
)(PreCollectContainer);
