import { request as Request } from "@octokit/request";
import btoa from "btoa-lite";

import { isAuthorizationRoute } from "./is-authorization-route";
import { getToken } from "./get-token";
import { requestWith2Fa } from "./request-with-2fa";
import {
  AnyResponse,
  EndpointDefaults,
  EndpointOptions,
  RequestParameters,
  Route,
  State
} from "./types";

export async function hook(
  state: State,
  request: typeof Request,
  route: Route | EndpointOptions,
  parameters?: RequestParameters
): Promise<AnyResponse> {
  const endpoint: EndpointDefaults = request.endpoint.merge(
    route as string,
    parameters
  );
  const basicAuthorization = `basic ${btoa(
    `${state.strategyOptions.username}:${state.strategyOptions.password}`
  )}`;

  if (isAuthorizationRoute(endpoint.url)) {
    endpoint.headers.authorization = basicAuthorization;
    return requestWith2Fa(state, endpoint as EndpointOptions, request);
  }

  const { token } = await getToken(state, {}, request);
  endpoint.headers.authorization = `token ${token}`;

  return request(endpoint as EndpointOptions);
}
