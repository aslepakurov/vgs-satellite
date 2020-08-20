import axios from 'axios';
import config from 'src/config/config';

export const getMitmLogs = () =>
  axios.get(`${config.mitmLogsEndpoint}/flows.json`);

export const replayMitmLog = (logId: string) =>
  axios.post(`${config.mitmLogsEndpoint}/flows/${logId}/replay`);

export const duplicateMitmLog = (logId: string) =>
  axios.post(`${config.mitmLogsEndpoint}/flows/${logId}/duplicate`);

export const deleteMitmLog = (logId: string) =>
  axios.delete(`${config.mitmLogsEndpoint}/flows/${logId}`);
