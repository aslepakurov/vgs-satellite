import * as React from 'react';
import FlowNav from './FlowNav';
import FlowButtons from './FlowButtons';
import RequestInfo from './RequestInfo';
import GeneralInfo from './GeneralInfo';
import Icon from 'src/components/atoms/Icon/Icon';
import { Modal, ModalBody } from 'reactstrap';
import { ILog, ILogFilters } from 'src/redux/interfaces/logs';
import { IRoute } from 'src/redux/interfaces/routes';
import { constructUriFromLog } from 'src/redux/utils/utils';

export interface IFlowViewProps {
  log: ILog;
  routes: IRoute[];
  logFilters: ILogFilters;
  showSpinner: boolean;
  onRuleCreate: (selectedPhase: string) => void;
  onClose: () => void;
  setPreRouteType: (type: 'inbound' | 'outbound') => void;
  onReplay: () => void;
  onDuplicate: () => void;
  onDelete: () => void;
}

export interface IFlowViewState {
  selectedTab: string;
  selectedPhase: string;
}

export default class FlowView extends React.Component<IFlowViewProps, IFlowViewState> {
  state = {
    selectedTab: 'general',
    selectedPhase: 'request',
  };

  selectTab(tab: string) {
    this.setState({
      selectedTab: tab,
      selectedPhase: 'request',
    });
  }

  selectPhase(phase: string) {
    if (phase === 'request' || phase === 'response') {
      this.setState({
        selectedPhase: phase,
      });
    }
  }

  matchingRoutes() {
    const matching = [];
    this.props.log.routes.data.forEach((logRoute) => {
      const route = this.props.routes.find(
        r => r.id === logRoute.attributes.route_id,
      );
      if (!!route) matching.push(route);
    });
    return matching;
  }

  hideSecureButton() {
    const log = this.props.log;
    const isMethodGet = log.http?.method === 'GET';
    const isInvalidPath = !log.path?.match(/^(https?:)\/\//) && !log.upstream;
    return isMethodGet || isInvalidPath;
  }

  handleRuleCreate() {
    this.props.onRuleCreate(this.state.selectedPhase.toUpperCase());
  }

  isMitmLog() {
    return this.props.log.hasOwnProperty('intercepted');
  }

  public render() {
    const { log, logFilters, onClose, showSpinner } = this.props;
    const { flow } = this.props.log;
    let tabs = ['general'];
    let headers = {};
    let body = {};

    if (flow) {
      tabs = [
        'general',
        'headers',
        'body',
      ];
      headers = {
        request: flow.request && flow.request.headers,
        response: flow.response && flow.response.headers,
        requestRewritten: flow.REQUEST_REWRITTEN && flow.REQUEST_REWRITTEN.headers,
        responseRewritten: flow.RESPONSE_REWRITTEN && flow.RESPONSE_REWRITTEN.headers,
      };
      body = {
        request: flow.request && flow.request.body,
        response: flow.response && flow.response.body,
        requestRewritten: flow.REQUEST_REWRITTEN && flow.REQUEST_REWRITTEN.body,
        responseRewritten: flow.RESPONSE_REWRITTEN && flow.RESPONSE_REWRITTEN.body,
      };

      Object.keys(body).forEach((key: string) => {
        if (body[key] && body[key].length > 3000) body[key] = 'Payload is too big to render';
      });
    }

    return (
      <Modal
        isOpen={true}
        toggle={onClose}
        fade={false}
        className="modal-lg flow-detail"
        data-role="log-details-modal"
      >
        <div className="modal-header">
          <h5 className="modal-title">Secure Data</h5>
          <Icon name="times" className="cursor-pointer" onClick={() => onClose()} />
        </div>
        <ModalBody>
          <FlowNav
            tabs={tabs}
            active={this.state.selectedTab}
            onSelectTab={tab => this.selectTab(tab)}
          />
          <FlowButtons
            activePhase={this.state.selectedPhase}
            selectedTab={this.state.selectedTab}
            hasPayload={!!this.props.log.flow}
            hideSecureButton={this.hideSecureButton()}
            onRuleCreate={() => this.handleRuleCreate()}
            onSelectPhase={phase => this.selectPhase(phase)}
            setPreRouteType={this.props.setPreRouteType}
            onReplay={this.props.onReplay}
            onDuplicate={this.props.onDuplicate}
            onDelete={this.props.onDelete}
            isMitmLog={this.isMitmLog()}
          />
          {this.state.selectedTab === 'general' && (
            <div className="mb-3 pt-0">
              <GeneralInfo
                log={log}
                validUri={constructUriFromLog(log)}
                showRouteType={true}
                showRequestMethod={true}
                showStatusCode={true}
              />
            </div>
          )}
          {this.state.selectedTab !== 'general' && (
            <RequestInfo
              headers={this.state.selectedTab === 'headers' && headers}
              body={this.state.selectedTab === 'body' && body}
              activePhase={this.state.selectedPhase}
            />
          )}
        </ModalBody>
      </Modal>
    );
  }
}
