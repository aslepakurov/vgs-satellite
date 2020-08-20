import config from 'src/config/config';
import { notify } from 'src/redux/utils/notifications';
import {
  getMitmLogs,
  replayMitmLog,
  duplicateMitmLog,
  deleteMitmLog,
} from '../apis/preCollect';

const ADD_PRE_COLLECT_LOGS = 'ADD_PRE_COLLECT_LOGS';
const SET_PRE_COLLECT_LOGS = 'SET_PRE_COLLECT_LOGS';
const ADD_PRE_COLLECT_LOG = 'ADD_PRE_COLLECT_LOG';
const UPDATE_PRE_COLLECT_LOG = 'UPDATE_PRE_COLLECT_LOG';
const REMOVE_PRE_COLLECT_LOG = 'REMOVE_PRE_COLLECT_LOG';
const CREATE_PRE_COLLECT_ROUTE = 'CREATE_PRE_COLLECT_ROUTE';
const CREATE_PRE_COLLECT_ROUTES = 'CREATE_PRE_COLLECT_ROUTES';
const TRIGGER_YAML_MODAL = 'TRIGGER_YAML_MODAL';
const SET_UPLOADED = 'SET_UPLOADED';

let socket: any = null;

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

  if (!socket) {
    socket = new WebSocket(`${config.mitmLogsEndpoint.replace('http', 'ws')}/updates`)
    socket.addEventListener('message', (message: any) => {
      const msg = JSON.parse(message.data)
      if (msg.resource === 'flows' && ['add', 'update', 'remove'].includes(msg.cmd)) {
        switch (msg.cmd) {
          case 'add':
            dispatch({
              type: ADD_PRE_COLLECT_LOG,
              data: msg.data,
            });
            break;
          case 'update':
            dispatch({
              type: UPDATE_PRE_COLLECT_LOG,
              data: msg.data,
            });
            break;
          case 'remove':
            dispatch({
              type: REMOVE_PRE_COLLECT_LOG,
              data: msg.data,
            });
            break;
          default:
            break;
        }
      }
    })
  }
}

export const replayRequest = (logId: string) => async () => {
  try {
    await replayMitmLog(logId);
    notify.success('Successfully replayed');
  } catch (error) {
    notify.error(`Something went wrong. ${error}`);
  }
}

export const duplicateRequest = (logId: string) => async () => {
  try {
    await duplicateMitmLog(logId);
    notify.success('Successfully duplicated');
  } catch (error) {
    notify.error(`Something went wrong. ${error}`);
  }
}

export const deleteRequest = (logId: string) => async () => {
  try {
    await deleteMitmLog(logId);
    notify.success('Successfully deleted');
  } catch (error) {
    notify.error(`Something went wrong. ${error}`);
  }
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
    case ADD_PRE_COLLECT_LOG:
      return ({
        ...state,
        list: [...state.list, action.data],
      });
    case UPDATE_PRE_COLLECT_LOG:
      return ({
        ...state,
        list: [
          ...state.list.filter(log => log.id !== action.data.id),
          action.data,
        ],
      });
    case REMOVE_PRE_COLLECT_LOG:
      return ({
        ...state,
        list: state.list.filter(log => log.id !== action.data),
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
