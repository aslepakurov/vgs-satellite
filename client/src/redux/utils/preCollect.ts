import { get } from 'lodash';
import { getParsedLogValue } from 'src/redux/utils/quick-integration';
import { unixToFormat } from 'src/redux/utils/utils';

export function harToFlow(harEntry, selectedPhase?: 'REQUEST' | 'RESPONSE') {
  const requestPost = get(harEntry, 'request.postData.text');
  const responsePost = get(harEntry, 'response.content.text');
  const contentType = get(harEntry, 'request.postData.mimeType');

  return Object.assign(harEntry, {
    flow: {
      request: {
        headers: harEntry.request.headers.map(h => [h.name, h.value]),
        body: requestPost,
      },
      response: {
        headers: harEntry.response.headers.map(h => [h.name, h.value]),
        body: responsePost,
      },
    },
    data: {
      value: {...getParsedLogValue(harEntry, selectedPhase), contentType},
    },
  });
}

export const mitmlogToFlow = (entry, selectedPhase) => {
  const contentTypeHeader = entry.request.headers.find(h => h[0] === 'Content-type');
  const flow = {
    ...entry,
    flow: {
      request: {
        headers: entry.request.headers,
        body: entry.request.content,
      },
      response: {
        headers: entry.response.headers,
        body: entry.response.content,
      },
    },
    data: {
      value: {
        ...getParsedLogValue(entry, selectedPhase),
        contentType: contentTypeHeader ? contentTypeHeader[1] : undefined,
      }
    }
  };
  return flow;
}

export const entryToFlow = (entry, selectedPhase) =>
  entry.hasOwnProperty('intercepted')
  ? mitmlogToFlow(entry, selectedPhase)
  : harToFlow(entry, selectedPhase);

export function harToLog(harEntry, routeType) {
  return Object.assign(harEntry, {
    path: harEntry.request.url,
    status: harEntry.request.status,
    occurred_at: harEntry.startedDateTime,
    expired_at: harEntry.startedDateTime,
    route_type: routeType,
    proxy_status: harEntry.response.status,
    routes: {
      data: [],
    },
    http: {
      method: harEntry.request.method,
    },
  });
}

export const mitmlogToLog = (entry, routeType) => {
  const dateFromTimestamp = unixToFormat(entry.request.timestamp_start);
  const log = {
    ...entry,
    path: entry.request.path,
    upstream: entry.request.host,
    scheme: entry.request.scheme,
    occurred_at: dateFromTimestamp,
    expired_at: dateFromTimestamp,
    route_type: routeType,
    proxy_status: entry.response?.status_code,
    routes: {
      data: [],
    },
    http: {
      method: entry.request.method,
    },
  };
  return log;
}

export const entryToLog = (entry, routeType) =>
  entry.hasOwnProperty('intercepted')
    ? mitmlogToLog(entry, routeType)
    : harToLog(entry, routeType);
