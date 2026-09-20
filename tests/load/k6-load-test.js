import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '5s', target: 20 },
    { duration: '15s', target: 50 },
    { duration: '5s', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<20'], // p95 should be < 20ms
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';

export default function () {
  // 1. Normal traffic
  let res = http.get(`${BASE_URL}/api/v1/products`);
  check(res, { 'status was 200 (normal)': (r) => r.status === 200 });

  // 2. Malicious traffic (SQLi)
  let malicious = http.get(`${BASE_URL}/api/v1/products?id=1' OR '1'='1`);
  check(malicious, { 'status was 403 (blocked)': (r) => r.status === 403 });

  sleep(0.5);
}
