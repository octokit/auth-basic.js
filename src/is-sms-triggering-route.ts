import { isAuthorizationRoute } from "./is-authorization-route";
import { EndpointOptions } from "./types";

export function isSmsTriggeringRoute(options: EndpointOptions): Boolean {
  return (
    ["PATCH", "PUT", "POST"].includes(options.method) &&
    isAuthorizationRoute(options.url)
  );
}
