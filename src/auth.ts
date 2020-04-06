import btoa from "btoa-lite";

import { getToken } from "./get-token";
import { requestWith2Fa } from "./request-with-2fa";
import {
  AuthOptions,
  State,
  Authentication,
  BasicAuthentication,
} from "./types";

export async function auth(
  state: State,
  options: AuthOptions = {}
): Promise<Authentication> {
  const credentials = btoa(
    `${state.strategyOptions.username}:${state.strategyOptions.password}`
  );

  if (options.type === "basic") {
    // send a dummy request to invoke 2Fa authorization. The endpoint does not exist
    // yet triggers 2Fa for both app & sms, see https://git.io/fjPJM
    try {
      await requestWith2Fa(state, {
        method: "PATCH",
        url: "/authorizations",
        headers: {
          authorization: `basic ${credentials}`,
        },
      });
    } catch (error) {
      if (error.status !== 404) {
        throw error;
      }

      // we are expecting a 404 error
    }

    return Object.assign(
      {
        type: "basic",
        username: state.strategyOptions.username,
        password: state.strategyOptions.password,
        credentials,
      },
      state.totp ? { totp: state.totp } : null
    ) as BasicAuthentication;
  }

  return getToken(state, options);
}
