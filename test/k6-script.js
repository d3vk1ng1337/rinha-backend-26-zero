// k6: carga de p99 sobre /fraud-score (keep-alive). Para A/B io_uring×epoll —
// mede DELTA de p99 e error rate. Accuracy é responsabilidade do gate, não aqui.
//
// uso: k6 run -e VUS=64 -e DURATION=60s -e HOST=http://localhost:9999 test/k6-script.js
import http from "k6/http";
import { check } from "k6";
import { SharedArray } from "k6/data";
import { Trend, Rate } from "k6/metrics";

const HOST = __ENV.HOST || "http://localhost:9999";
const VUS = parseInt(__ENV.VUS || "64");
const DURATION = __ENV.DURATION || "60s";

const entries = new SharedArray("entries", function () {
  const raw = JSON.parse(open("./test-data.json"));
  return raw.entries.map((e) => JSON.stringify(e.request));
});

const dur = new Trend("fraud_ms", true);
const errs = new Rate("fraud_errors");

export const options = {
  scenarios: {
    load: {
      executor: "constant-vus",
      vus: VUS,
      duration: DURATION,
    },
  },
  thresholds: {
    // espelha o gate de robustez da rinha: <15% falha; alvo p99 sub-ms
    fraud_errors: ["rate<0.15"],
    "http_req_duration{expected_response:true}": ["p(99)<5"],
  },
};

const params = { headers: { "Content-Type": "application/json" } };

export default function () {
  const body = entries[Math.floor(Math.random() * entries.length)];
  const res = http.post(`${HOST}/fraud-score`, body, params);
  dur.add(res.timings.duration);
  const ok = check(res, {
    "200": (r) => r.status === 200,
  });
  errs.add(!ok);
}
