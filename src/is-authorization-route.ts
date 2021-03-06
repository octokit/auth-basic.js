const PATHS = [
  "/authorizations",
  "/authorizations/clients/:client_id",
  "/authorizations/clients/:client_id/:fingerprint",
  "/authorizations/:authorization_id",
];

// CREDIT: Simon Grondin (https://github.com/SGrondin)
// https://github.com/octokit/plugin-throttling.js/blob/45c5d7f13b8af448a9dbca468d9c9150a73b3948/lib/route-matcher.js
function routeMatcher(paths: string[]) {
  // EXAMPLE. For the following paths:
  /* [
      "/orgs/:org/invitations",
      "/repos/:owner/:repo/collaborators/:username"
  ] */

  const regexes = paths.map((p) =>
    p
      .split("/")
      .map((c) => (c.startsWith(":") ? "(?:.+?)" : c))
      .join("/")
  );
  // 'regexes' would contain:
  /* [
      '/orgs/(?:.+?)/invitations',
      '/repos/(?:.+?)/(?:.+?)/collaborators/(?:.+?)'
  ] */

  const regex = `^(?:${regexes.map((r) => `(?:${r})`).join("|")})[^/]*$`;
  // 'regex' would contain:
  /*
    ^(?:(?:\/orgs\/(?:.+?)\/invitations)|(?:\/repos\/(?:.+?)\/(?:.+?)\/collaborators\/(?:.+?)))[^\/]*$

    It may look scary, but paste it into https://www.debuggex.com/
    and it will make a lot more sense!
  */

  return new RegExp(regex, "i");
}

const REGEX = routeMatcher(PATHS);

export function isAuthorizationRoute(url?: string): Boolean {
  return !!url && REGEX.test(url);
}
