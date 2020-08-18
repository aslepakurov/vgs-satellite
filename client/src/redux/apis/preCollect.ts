import axios from 'axios';
import config from 'src/config/config';

export const getMitmLogs = () =>
  axios.get(`${config.mitmLogsEndpoint}/flows.json`);
