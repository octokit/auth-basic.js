import { isAuthorizationRoute } from "./is-authorization-route";
import { Endpoint } from "./types";

export function isSmsTriggeringRoute(options: Endpoint): Boolean {
  return (
    ["PATCH", "PUT", "POST"].includes(options.method) &&
    isAuthorizationRoute(options.url)
  );
}
