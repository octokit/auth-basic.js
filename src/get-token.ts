import btoa from "btoa-lite";

import { requestWith2Fa } from "./request-with-2fa";
import {
  AuthOptions,
  EndpointOptions,
  RequestInterface,
  State,
  TokenAuthentication,
} from "./types";

export async function getToken(
  state: State,
  authOptions: AuthOptions,
  request?: RequestInterface
): Promise<TokenAuthentication> {
  if (state.token && !authOptions.refresh) {
    return state.token;
  }

  const basicAuthorization = `basic ${btoa(
    `${state.strategyOptions.username}:${state.strategyOptions.password}`
  )}`;
  const timestamp = new Date().toISOString().substr(0, 10);
  const fingerprintDefault = state.strategyOptions.token.note
    ? undefined
    : Math.random().toString(36).substr(2);
  const fingerprint =
    state.strategyOptions.token.fingerprint || fingerprintDefault;
  const note =
    state.strategyOptions.token.note || `octokit ${timestamp} ${fingerprint}`;
  const scopes = state.strategyOptions.token.scopes || [];
  const noteUrl =
    state.strategyOptions.token.noteUrl ||
    "https://github.com/octokit/auth-basic.js#readme";

  const options = Object.assign(
    {
      method: "POST",
      url: "/authorizations",
      headers: {
        authorization: basicAuthorization,
      },
      note,
      note_url: noteUrl,
      scopes,
    },
    fingerprint ? { fingerprint } : null,
    state.strategyOptions.token.clientId
      ? {
          client_id: state.strategyOptions.token.clientId,
          client_secret: state.strategyOptions.token.clientSecret,
        }
      : null
  ) as EndpointOptions;

  const {
    data: { id, token },
  } = await requestWith2Fa(state, options, request);

  state.token = {
    type: "token",
    tokenType: "oauth",
    id,
    token,
    username: state.strategyOptions.username,
  };

  return state.token;
}
