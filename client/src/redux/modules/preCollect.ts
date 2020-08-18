import { getMitmLogs } from '../apis/preCollect';

const ADD_PRE_COLLECT_LOGS = 'ADD_PRE_COLLECT_LOGS';
const SET_PRE_COLLECT_LOGS = 'SET_PRE_COLLECT_LOGS';
const CREATE_PRE_COLLECT_ROUTE = 'CREATE_PRE_COLLECT_ROUTE';
const CREATE_PRE_COLLECT_ROUTES = 'CREATE_PRE_COLLECT_ROUTES';
const TRIGGER_YAML_MODAL = 'TRIGGER_YAML_MODAL';
const SET_UPLOADED = 'SET_UPLOADED';

export function addPrecollectLogs(logs) {
  return (dispatch) => {
    dispatch({
      type: ADD_PRE_COLLECT_LOGS,
      data: logs,
    });
    dispatch({
      type: SET_UPLOADED,
      data: true,
    });
  };
}

export function createPrecollectRoute(route) {
  return (dispatch) => {
    dispatch({
      type: CREATE_PRE_COLLECT_ROUTE,
      data: route,
    });
  };
}

export function createPrecollectRoutes(inbound, outbound) {
  return (dispatch) => {
    dispatch({
      type: CREATE_PRE_COLLECT_ROUTES,
      data: { inbound, outbound },
    });
  };
}

export function triggerYamlModal(open: boolean) {
  return (dispatch) => {
    dispatch({
      type: TRIGGER_YAML_MODAL,
      data: open,
    });
  };
}

export const fetchFlows = () => async (dispatch: any) => {
  const response = await getMitmLogs();
  dispatch({
    type: SET_PRE_COLLECT_LOGS,
    data: response.data,
  });
  dispatch({
    type: SET_UPLOADED,
    data: false,
  });
}

const initialState = {
  list: [],
  route: null,
  routes: {
    inbound: null,
    outbound: null,
  },
  isYamlModalOpen: false,
  isUploaded: false,
};

export default function reducer(state = initialState, action: any) {
  switch (action.type) {
    case ADD_PRE_COLLECT_LOGS:
      return ({
        ...state,
        list: [...state.list, ...action.data],
      });
    case SET_PRE_COLLECT_LOGS:
      return ({
        ...state,
        list: action.data,
      });
    case CREATE_PRE_COLLECT_ROUTE:
      return ({
        ...state,
        route: action.data,
      });
    case CREATE_PRE_COLLECT_ROUTES:
      return ({
        ...state,
        routes: { inbound: action.data.inbound, outbound: action.data.outbound },
      });
    case TRIGGER_YAML_MODAL:
      return ({
        ...state,
        isYamlModalOpen: action.data,
      });
    case SET_UPLOADED:
      return ({
        ...state,
        isUploaded: action.data,
      });
    default:
      return state;
  }
}
