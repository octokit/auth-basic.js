import { getUserAgent } from "universal-user-agent";
import { request } from "@octokit/request";

import { auth } from "./auth";
import { hook } from "./hook";
import {
  StrategyInterface,
  StrategyOptions,
  AuthOptions,
  Authentication
} from "./types";
import { VERSION } from "./version";

export type Types = {
  StrategyOptions: StrategyOptions;
  AuthOptions: AuthOptions;
  Authentication: Authentication;
};

export const createBasicAuth: StrategyInterface = function createBasicAuth(
  options: StrategyOptions
) {
  console.warn(`[@octokit/auth-basic] Basic authentication has been deprecated. See https://github.com/octokit/auth-basic.js/#deprecation`)

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
};
