import {
  getRoutes,
  createRoute,
  deleteRouteById,
} from 'src/redux/apis/routes';
import { notify } from 'src/redux/utils/notifications';

const SET_LOADING = 'SET_LOADING';
const GET_ROUTES_LIST = 'GET_ROUTES_LIST';
const DELETE_ROUTE = 'DELETE_ROUTE';
const TOGGLE_ROUTE_CONFIRM_DELETE_MODAL = 'TOGGLE_ROUTE_CONFIRM_DELETE_MODAL';
const SET_SAVE_PROGRESS = 'SET_SAVE_PROGRESS';

export function fetchRoutes() {
  return async (dispatch: any) => {
    dispatch({
      type: SET_LOADING,
      data: true,
    });
    const response = await getRoutes();
    dispatch({
      type: GET_ROUTES_LIST,
      data: response.data,
    });
    dispatch({
      type: SET_LOADING,
      data: false,
    });
  };
}

export function saveRoute(route: IRoute) {
  return async (dispatch: any) => {
    try {
      dispatch({
        type: SET_SAVE_PROGRESS,
        data: true,
      });
      await createRoute(route);
      notify.success('Route created successfully');
      const response = await getRoutes();
      dispatch({
        type: GET_ROUTES_LIST,
        data: response.data,
      });
    } catch (error) {
      notify.error(error);
    } finally {
      dispatch({
        type: SET_SAVE_PROGRESS,
        data: false,
      });
    }
  };
}

export function deleteRoute(routeId: string) {
  return async (dispatch: any) => {
    await deleteRouteById(routeId);
    notify.success('Route was deleted');
    dispatch({
      type: DELETE_ROUTE,
      data: routeId,
    });
  };
}

export function toggleRouteConfirmDeleteModal(isOpen: boolean) {
  return (dispatch: any) => {
    dispatch({
      type: TOGGLE_ROUTE_CONFIRM_DELETE_MODAL,
      data: {
        isOpen,
      },
    });
  };
}

const initialState: IRoutesState = {
  isLoading: false,
  list: [],
  currentRoute: null,
  isSaveInProgress: false,
  routeTemplates: {
    list: {},
    isListLoading: false,
    isDetailsLoading: false,
    selectedKey: null,
  },
  createdRoute: null,
  routeConfirmDeleteModal: {
    isOpen: false,
  },
};

export default function reducer(state = initialState, action: any) {
  switch (action.type) {
    case SET_LOADING:
      return {
        ...state,
        isLoading: action.data,
      };
    case GET_ROUTES_LIST:
      return {
        ...state,
        list: action.data,
      };
    case TOGGLE_ROUTE_CONFIRM_DELETE_MODAL:
      return {
        ...state,
        routeConfirmDeleteModal: action.data,
      };
    case DELETE_ROUTE:
      return {
        ...state,
        routeConfirmDeleteModal: {
          isOpen: false,
        },
      };
    case SET_SAVE_PROGRESS:
      return {
        ...state,
        isSaveInProgress: action.data,
      };
    default:
      return state;
  }
}
