import moment from 'moment';
import classnames from 'classnames';
import parseUrl from 'url-parse';
import { volatileRulesRegex } from 'src/data/regex';
import { ILog } from 'src/redux/interfaces/logs';
import randomId from './random-id';

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
  const isPathPrependable = !!log.scheme && !log.upstream.startsWith(log.scheme) && !log.upstream?.match(/^\//);
  return isPathSufficient
    ? log.path
    : `${isPathPrependable ? log.scheme + '://' : ''}${log.upstream ?? ''}${isPathAppendable ? log.path : ''}`;
}

export const getFiltersWithoutOperations = (route: IRoute) => route.entries.filter(entry => !entry.operations);
