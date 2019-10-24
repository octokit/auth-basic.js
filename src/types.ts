import * as OctokitTypes from "@octokit/types";

export type AnyResponse = OctokitTypes.OctokitResponse<any>;
export type EndpointDefaults = OctokitTypes.EndpointDefaults;
export type EndpointOptions = OctokitTypes.EndpointOptions;
export type RequestParameters = OctokitTypes.RequestParameters;
export type Route = OctokitTypes.Route;
export type RequestInterface = OctokitTypes.RequestInterface;

type TokenOptions = {
  [option: string]: any;
};
export type StrategyOptions = {
  username: string;
  password: string;
  on2Fa(): string | Promise<string>;
  token?: TokenOptions;
  request?: RequestInterface;
};

export type WithRequest = {
  request: RequestInterface;
};

export type AuthOptions = {
  type?: "token" | "basic";
  refresh?: Boolean;
};

export type State = {
  strategyOptions: StrategyOptions & { token: TokenOptions };
  request: RequestInterface;
  token?: TokenAuthentication;
  totp?: string;
};

export type Token = string;
export type BasicAuthentication = {
  type: "basic";
  username: string;
  password: string;
};
export type TokenAuthentication = {
  type: "token";
  tokenType: "oauth";
  id: number;
  token: Token;
  username: string;
};
export type Authentication = BasicAuthentication | TokenAuthentication;
