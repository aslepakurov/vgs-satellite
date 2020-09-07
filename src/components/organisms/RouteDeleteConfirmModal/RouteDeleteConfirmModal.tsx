import React from 'react';
import Icon from 'src/components/atoms/Icon/Icon';
import {
  Alert, Button,
  Modal,
  ModalBody, ModalFooter,
} from 'reactstrap';
import { IRoute } from 'src/redux/interfaces/routes';
import RouteSummary from 'src/components/organisms/RoutesList/RouteSummary';
import { getFiltersWithoutOperations } from 'src/redux/utils/utils';

interface IRouteDeleteConfirmModalProps {
  route: IRoute;
  isLoading: boolean;
  isModalOpen: boolean;
  toggleModal: (isOpen: boolean) => void;
  routeDeleteHandler: (routeId: string) => void;
}

const RouteDeleteConfirmModal: React.FunctionComponent<IRouteDeleteConfirmModalProps> = (props) => {

  const { isLoading, isModalOpen, toggleModal, routeDeleteHandler, route } = props;
  const entries = getFiltersWithoutOperations(route);

  return (
    <Modal isOpen={isModalOpen} toggle={() => toggleModal(!isModalOpen)} fade={false}>
      <div className="modal-header">
        <h5 className="modal-title">Are you sure you want to delete this route?</h5>
        <Icon name="times" onClick={() => toggleModal(!isModalOpen)}/>
      </div>
      <ModalBody>
        {isLoading ?
          <div className="message-loading my-5">
            <i className="fa fa-spinner fa-spin fa-fw"/>
            <span> Loading...</span>
          </div>
          :
          <div>
            {!!entries.length &&
            <Alert color="warning" role="alert">
              <div>
                <p className="m-0">{route.upstreamUrl}</p>
                <RouteSummary entries={entries}/>
              </div>
            </Alert>
            }
            <p className="m-0 text-muted">This route will be deleted immediately. There is no undo.</p>
          </div>}
      </ModalBody>
      <ModalFooter>
        <Button
          onClick={() => routeDeleteHandler(route.id)}
          color="link"
          data-role="modal-submit-button"
        >
          Delete
        </Button>
        <Button
          color="primary"
          data-role={'close-modal'}
          onClick={() => toggleModal(!isModalOpen)}
        >
          Cancel
        </Button>
      </ModalFooter>
    </Modal>
  );
};

export default RouteDeleteConfirmModal;
