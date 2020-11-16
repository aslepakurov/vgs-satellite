import moment from 'moment';
import classnames from 'classnames';
import parseUrl from 'url-parse';
import randomId from './random-id';
import { volatileRulesRegex } from 'src/data/regex';
import { includes, flattenDeep, uniq } from 'lodash';
import { ILog, ILogFilters } from 'src/redux/interfaces/logs';
import { IRoute, IEntry } from 'src/redux/interfaces/routes';

export const dateToFormat = (date: moment.MomentInput, format: string) => moment(date).format(format);

export function formatDate(date) {
  if (moment().isSame(date, 'day')) {
    return moment.utc(date).local().format('[Today] HH:mm:ss');
  } else {
    return moment.utc(date).local().format('YYYY-MM-DD HH:mm:ss');
  }
}

export function unixToFormat(dateUnix: number, format?: string) {
  return moment.unix(dateUnix).format(format);
}

export function dateFromNow(date) {
  return moment(date).fromNow();
}

export function nowBeforeDate(date) {
  return moment().isBefore(date);
}

export function isVolatile(name) {
  return name.match(volatileRulesRegex);
}

export function badgeColor(statusCode) {
  return classnames({
    danger: statusCode >= 500,
    success: statusCode >= 200 && statusCode <= 299,
    secondary: statusCode >= 300 && statusCode <= 399,
    warning: statusCode >= 400 && statusCode <= 499,
  });
}

export function isEqual(stringOne: string, stringTwo: string) {
  return stringOne.toLowerCase() === stringTwo.toLowerCase();
}

export function getQueryParameters(url: string) {
  return parseUrl(url).query;
}

export const generateRouteName = (hostname?: string) => {
  const routeName = randomId();
  return routeName;
};

export function constructUriFromLog(log: ILog) {
  const isPathSufficient = !!log.path?.match(/^(https?:)\/\//);
  const isPathAppendable = !log.upstream?.match(/\/$/) && !!log.path?.match(/^\//);
  const isPathPrependable = !!log.scheme && !log.upstream.startsWith(`${log.scheme}:`) && !log.upstream?.match(/^\//);
  return isPathSufficient
    ? log.path
    : `${isPathPrependable ? log.scheme + '://' : ''}${log.upstream ?? ''}${isPathAppendable ? log.path : ''}`;
}

export const getFiltersWithoutOperations = (route: IRoute) => route.entries.filter(entry => !entry.operations);

export function isValidHostname(hostname: string) {
  const hostnameRegex = /^\s*((?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|\b-){0,61}[0-9A-Za-z])?(?:\.{1,}[0-9A-Za-z](?:(?:[0-9A-Za-z]|\b-){0,61}[0-9A-Za-z])?){1,}?(:[0-9]{1,4}){0,1})\s*$/; // tslint:disable-line
  return hostnameRegex.test(hostname);
}

export const hostFromUri = (destOverride: string) => {
  const url = new URL(destOverride);
  return url.hostname;
};

export const hostnameFromUri = (destOverride: string) => destOverride.replace(/^(.*\/\/)/, '');

export function removeQueryParameters(url: string) {
  const queryParameter = parseUrl(url).query;
  return url.replace(queryParameter, '');
};

export const isOperatorExist = (rules: any, operator: string) => includes(rules.map(rule => rule.operator), operator);

export function isJSON(data) {
  try {
    JSON.parse(data);
    return true;
  } catch {
    return false;
  }
}

export function getOperationsName(operations: string) {
  const operationsJson = isJSON(operations) && JSON.parse(operations);
  if (Array.isArray(operationsJson)) {
    const operationsArray = operationsJson.map(op => op['@type']);
    return operationsArray.join(', ').replace(/(type\.googleapis\.com\/)|(Config)/g, '');
  } else {
    return '';
  }
}

export function isRegExp(value: string) {
  if (!value) {
    return true;
  }
  try {
    const regExp = new RegExp(value);
    return true;
  } catch (e) {
    return false;
  }
}

export function mapMatchingFilters(
  routes: IRoute[],
  logFilters: ILogFilters,
) {
  if (logFilters?.filters?.length) {
    const matchingFilters = []
      .concat(
        ...routes.map(route =>
          logFilters.filters.map((f) => {
            const matchedFilter = route.entries.find(
              entry => entry.id === f.id,
            );
            return matchedFilter && matchedFilter.id;
          }),
        ),
      )
      .filter(el => el != null);
    return matchingFilters;
  } else {
    return [];
  }
}

export const matchedInActivePhase = (entries: IEntry[], activePhase: string) =>
  entries.find(entry => entry.phase.toLowerCase() === activePhase);

export const isInCollection = (id: string, arr?: any[]) => !!(arr && arr.find(obj => obj.id === id));

export function flatExpressions(filterRule) {
  const allExpressions = (rule) => {
    const arr = [];
    if (!!rule.expression && rule.expression.field) {
      arr.push(rule.expression.field);
    }
    if (rule.rules && !!rule.rules.length) {
      rule.rules.forEach((innerRule) => {
        arr.push(allExpressions(innerRule));
      });
    }
    return arr;
  };

  return uniq(flattenDeep(allExpressions(filterRule)))
    .toString()
    .replace(/,/g, ', ');
}

export function removeCharset(value: string, entry: IEntry) {
  const { transformer_config_map } = entry;
  const { charset, ...noCharset } = { ...transformer_config_map };
  return charset === value ?  { ...entry, transformer_config_map: noCharset } : entry;
}
