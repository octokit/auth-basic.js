import { getUserAgent } from "universal-user-agent";
import { request } from "@octokit/request";

import { auth } from "./auth";
import { hook } from "./hook";
import { StrategyOptions } from "./types";
import { VERSION } from "./version";

export function createBasicAuth(options: StrategyOptions) {
  ["username", "password", "on2Fa"].forEach((option: string) => {
    if (!options.hasOwnProperty(option)) {
      throw new Error(`[@octokit/auth-basic] ${option} option is required`);
    }
  });

  const strategyOptions = Object.assign(
    {
      token: {}
    },
    options
  );

  const state = {
    strategyOptions,
    request:
      strategyOptions.request ||
      request.defaults({
        baseUrl: "https://api.github.com",
        headers: {
          "user-agent": `octokit-auth-basic.js/${VERSION} ${getUserAgent()}`
        }
      })
  };

  return Object.assign(auth.bind(null, state), {
    hook: hook.bind(null, state)
  });
}
