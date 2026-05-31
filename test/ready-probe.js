// Isola o piso de I/O: GET /ready percorre o MESMO caminho de rede
// (LB→SCM_RIGHTS→worker→io_uring recv→send) mas SEM normalize+search.
// Se p99(/ready) ≈ p99(/fraud-score), a latência é o piso de rede/VM, não a IVF.
import http from "k6/http";
import { check } from "k6";

export const options = {
  summaryTrendStats: ["avg", "med", "p(95)", "p(99)", "max"],
  scenarios: {
    default: {
      executor: "ramping-arrival-rate",
      startRate: 1,
      timeUnit: "1s",
      preAllocatedVUs: 100,
      maxVUs: 250,
      stages: [{ duration: "120s", target: 900 }],
    },
  },
};

export default function () {
  const r = http.get(`${__ENV.HOST || "http://localhost:9999"}/ready`);
  check(r, { "200": (x) => x.status === 200 });
}
