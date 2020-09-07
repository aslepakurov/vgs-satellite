import axios from 'axios';
import config from 'src/config/config';
import { IRoute } from 'src/redux/interfaces/routes';

export const getRoutes = () =>
  axios.get(`${config.mitmLogsEndpoint}/route`);

export const getRouteById = (routeId: string) =>
  axios.get(`${config.mitmLogsEndpoint}/route/${routeId}`);

export const createRoute = (route: IRoute) =>
  axios.post(`${config.mitmLogsEndpoint}/route`, {
    data: {
      attributes: route.attributes || route,
      type: 'rule-chains',
    },
  });

export const updateRoute = (route: IRoute) =>
  axios.put(`${config.mitmLogsEndpoint}/route`, route);

export const deleteRouteById = (routeId: string) =>
  axios.delete(`${config.mitmLogsEndpoint}/route/${routeId}`);







// export function getRoutesByVault(vault: IVault) {
//   const url = `${vault.links.vault_management_api}/rule-chains`;
//   const options = {
//     headers: makeHeaders({ 'VGS-Tenant': vault.data.identifier }),
//   };
//   return fetchJSONApi(url, options);
// }

// export function updateRouteForVault(vault: IVault, route: IRoute, version?: string) {
//   let url = `${vault.links.vault_management_api}/rule-chains/${route.id || route.attributes.id}`;
//   if (version) {
//     url = `${url}?resource_meta[revert_version]=${version}`;
//   }
//   const options = {
//     method: 'PUT',
//     headers: makeHeaders({ 'VGS-Tenant': vault.data.identifier }),
//     data: {
//       data: {
//         attributes: route.attributes || route,
//         type: 'rule-chains',
//       },
//     },
//   };
//   return fetchJSONApi(url, options);
// }

// export function createRouteRequest(vault: IVault, route: IRoute) {
//   const url = `${vault.links.vault_management_api}/rule-chains`;
//   const options = {
//     method: 'POST',
//     headers: makeHeaders({ 'VGS-Tenant': vault.data.identifier }),
//     data: {
//       data: {
//         attributes: route.attributes || route,
//         type: 'rule-chains',
//       },
//     },
//   };
//   return fetchJSONApi(url, options);
// }

// export function getRouteRequest(vault: IPartialVault, routeId: string) {
//   const url = `${vault.links.vault_management_api}/rule-chains/${routeId}`;
//   const options = {
//     headers: makeHeaders({ 'VGS-Tenant': vault.data.identifier }),
//   };
//   return fetchJSONApi(url, options);
// }

// export function getRouteTemplatesRequest() {
//   const url = config.gitApiRoutesTemplatesRequestUrl;

//   return fetchApi(url, {});
// }

// export function getExactRouteTemplateRequest(url: string) {
//   return fetchApi(url, {});
// }

// export function deleteRouteRequest(vault: IVault, routeId: string) {
//   const url = `${vault.links.vault_management_api}/rule-chains/${routeId}`;
//   const options = {
//     method: 'DELETE',
//     headers: makeHeaders({ 'VGS-Tenant': vault.data.identifier }),
//   };
//   return fetchJSONApi(url, options);
// }
