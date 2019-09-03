import { request } from "@octokit/request";
import fetchMock, { MockMatcherFunction } from "fetch-mock";
import { Response } from "node-fetch";
import lolex from "lolex";

import { createBasicAuth } from "../src/index";
import { TokenAuthentication } from "../src/types";

type FetchCall = [string, RequestInit];

// We have to define the same `POST /authorizations` route multiple times.
// In order to make that possible, the `overwriteRoutes` option has to be configured
// See http://www.wheresrhys.co.uk/fetch-mock/#usageconfiguration
fetchMock.config.overwriteRoutes = false;

beforeAll(() => {
  // Math.random is used to generate the token fingerprint,
  // unless `token.fingerprint` option was passed. The fingerprint is
  // calculated using `Math.random().toString(36).substr(2)`, so the
  // default fingerprint is always `"4feornbt361"`.
  Math.random = jest.fn().mockReturnValue(0.123);

  // A timestamp is added to the default token note, e.g.
  // "octokit 2019-07-04 4feornbt361". Lolex mocks the Date class so
  // `new Date()` always returns `new Date(0)` by default.
  const clock = lolex.install({
    now: 0,
    toFake: ["Date"]
  });

  beforeEach(() => {
    clock.reset();
  });
});

afterAll(() => {
  // @ts-ignore
  Math.random.mockReset();
});

test("README example (token authentication)", async () => {
  const matcher: MockMatcherFunction = (url, { body, headers }) => {
    expect(url).toEqual("https://api.github.com/authorizations");
    expect(JSON.parse(String(body))).toStrictEqual({
      fingerprint: "4feornbt361",
      note: "octokit 1970-01-01 4feornbt361",
      note_url: "https://github.com/octokit/auth-basic.js#readme",
      scopes: []
    });
    expect(headers).toStrictEqual({
      accept: "application/vnd.github.v3+json",
      authorization: "basic b2N0b2NhdDpzZWNyZXQ=",
      "content-type": "application/json; charset=utf-8",
      "user-agent": "test"
    });
    return true;
  };
  const responseBody = {
    id: 123,
    token: "1234567890abcdef1234567890abcdef12345678"
  };

  const mock = fetchMock.sandbox().postOnce(matcher, responseBody);

  const auth = createBasicAuth({
    username: "octocat",
    password: "secret",
    async on2Fa() {
      throw new Error("Should not ask for 2FA code");
    },
    request: request.defaults({
      headers: {
        "user-agent": "test"
      },
      request: {
        fetch: mock
      }
    })
  });

  const authentication = await auth();

  expect(authentication).toEqual({
    type: "token",
    token: "1234567890abcdef1234567890abcdef12345678",
    tokenType: "oauth",
    id: 123,
    username: "octocat"
  });
});

test("README example (basic authentication)", async () => {
  const expectedRequestHeaders = {
    accept: "application/vnd.github.v3+json",
    authorization: "basic b2N0b2NhdDpzZWNyZXQ=",
    "content-length": 0,
    "user-agent": "test"
  };

  const matcher1: MockMatcherFunction = (url, { body, headers }) => {
    expect(url).toEqual("https://api.github.com/authorizations");
    expect(headers).toStrictEqual(expectedRequestHeaders);
    return true;
  };
  const matcher2: MockMatcherFunction = (url, { body, headers }) => {
    expect(url).toEqual("https://api.github.com/authorizations");
    expect(headers).toStrictEqual({
      ...expectedRequestHeaders,
      "x-github-otp": "123456"
    });
    return true;
  };

  const response1 = new Response("Unauthorized", {
    status: 401,
    headers: {
      "x-github-otp": "required; app"
    }
  });
  const response2 = {
    status: 404,
    headers: {}
  };

  const mock = fetchMock
    .sandbox()
    .patchOnce(matcher1, response1)
    .patchOnce(matcher2, response2);

  const requestMock = request.defaults({
    headers: {
      "user-agent": "test"
    },
    request: {
      fetch: mock
    }
  });

  const auth = createBasicAuth({
    username: "octocat",
    password: "secret",
    async on2Fa() {
      return "123456";
    },

    request: requestMock
  });

  const authentication = await auth({ type: "basic" });

  expect(mock.done()).toBeTruthy();
  expect(authentication).toEqual({
    type: "basic",
    username: "octocat",
    password: "secret",
    totp: "123456",
    credentials: "b2N0b2NhdDpzZWNyZXQ="
  });
});

test("auth({type: 'token'})", async () => {
  const matcher: MockMatcherFunction = (url, { body, headers }) => {
    expect(url).toEqual("https://api.github.com/authorizations");
    expect(JSON.parse(String(body))).toStrictEqual({
      fingerprint: "4feornbt361",
      note: "octokit 1970-01-01 4feornbt361",
      note_url: "https://github.com/octokit/auth-basic.js#readme",
      scopes: []
    });
    expect(headers).toStrictEqual({
      accept: "application/vnd.github.v3+json",
      authorization: "basic b2N0b2NhdDpzZWNyZXQ=",
      "content-type": "application/json; charset=utf-8",
      "user-agent": "test"
    });
    return true;
  };
  const responseBody = {
    id: 123,
    token: "1234567890abcdef1234567890abcdef12345678"
  };

  const auth = createBasicAuth({
    username: "octocat",
    password: "secret",
    async on2Fa() {
      throw new Error("Should not ask for 2FA code");
    },
    request: request.defaults({
      headers: {
        "user-agent": "test"
      },
      request: {
        fetch: fetchMock.sandbox().postOnce(matcher, responseBody)
      }
    })
  });

  const authentication = await auth({ type: "token" });

  expect(authentication).toEqual({
    type: "token",
    token: "1234567890abcdef1234567890abcdef12345678",
    tokenType: "oauth",
    id: 123,
    username: "octocat"
  });
});

test("auth({type: 'basic'}) without 2Fa enabled", async () => {
  const matcher: MockMatcherFunction = (url, { body, headers }) => {
    expect(url).toEqual("https://api.github.com/authorizations");
    expect(headers).toStrictEqual({
      accept: "application/vnd.github.v3+json",
      authorization: "basic b2N0b2NhdDpzZWNyZXQ=",
      "content-length": 0,
      "user-agent": "test"
    });
    return true;
  };

  const auth = createBasicAuth({
    username: "octocat",
    password: "secret",
    async on2Fa() {
      throw new Error("Should not ask for 2FA code");
    },
    request: request.defaults({
      headers: {
        "user-agent": "test"
      },
      request: {
        fetch: fetchMock.sandbox().patchOnce(matcher, { status: 404 })
      }
    })
  });

  const authentication = await auth({ type: "basic" });

  expect(authentication).toStrictEqual({
    type: "basic",
    username: "octocat",
    password: "secret",
    credentials: "b2N0b2NhdDpzZWNyZXQ="
  });
});

test("2fa", async () => {
  const expectedRequestBody = {
    fingerprint: "4feornbt361",
    note: "octokit 1970-01-01 4feornbt361",
    note_url: "https://github.com/octokit/auth-basic.js#readme",
    scopes: []
  };
  const expectedRequestHeaders = {
    accept: "application/vnd.github.v3+json",
    authorization: "basic b2N0b2NhdDpzZWNyZXQ=",
    "content-type": "application/json; charset=utf-8",
    "user-agent": "test"
  };

  const matcher1: MockMatcherFunction = (url, { body, headers }) => {
    expect(url).toEqual("https://api.github.com/authorizations");
    expect(JSON.parse(String(body))).toStrictEqual(expectedRequestBody);
    expect(headers).toStrictEqual(expectedRequestHeaders);
    return true;
  };
  const matcher2: MockMatcherFunction = (url, { body, headers }) => {
    expect(url).toEqual("https://api.github.com/authorizations");
    expect(JSON.parse(String(body))).toStrictEqual(expectedRequestBody);
    expect(headers).toStrictEqual({
      ...expectedRequestHeaders,
      "x-github-otp": "123456"
    });
    return true;
  };

  const response1 = new Response("Unauthorized", {
    status: 401,
    headers: {
      "x-github-otp": "required; app"
    }
  });
  const response2 = {
    id: 123,
    token: "1234567890abcdef1234567890abcdef12345678"
  };

  const auth = createBasicAuth({
    username: "octocat",
    password: "secret",
    async on2Fa() {
      return "123456";
    },
    request: request.defaults({
      headers: {
        "user-agent": "test"
      },
      request: {
        fetch: fetchMock
          .sandbox()
          .postOnce(matcher1, response1)
          .postOnce(matcher2, response2)
      }
    })
  });

  const authentication = await auth();

  expect(authentication).toEqual({
    type: "token",
    token: "1234567890abcdef1234567890abcdef12345678",
    tokenType: "oauth",
    id: 123,
    username: "octocat"
  });
});

test("2fa with invalid time-based one-time password", async () => {
  const expectedRequestBody = {
    fingerprint: "4feornbt361",
    note: "octokit 1970-01-01 4feornbt361",
    note_url: "https://github.com/octokit/auth-basic.js#readme",
    scopes: []
  };
  const expectedRequestHeaders = {
    accept: "application/vnd.github.v3+json",
    authorization: "basic b2N0b2NhdDpzZWNyZXQ=",
    "content-type": "application/json; charset=utf-8",
    "user-agent": "test"
  };

  const matcher1: MockMatcherFunction = (url, { body, headers }) => {
    expect(url).toEqual("https://api.github.com/authorizations");
    expect(JSON.parse(String(body))).toStrictEqual(expectedRequestBody);
    expect(headers).toStrictEqual(expectedRequestHeaders);
    return true;
  };
  const matcher2: MockMatcherFunction = (url, { body, headers }) => {
    expect(url).toEqual("https://api.github.com/authorizations");
    expect(JSON.parse(String(body))).toStrictEqual(expectedRequestBody);
    expect(headers).toStrictEqual({
      ...expectedRequestHeaders,
      "x-github-otp": "123456"
    });
    return true;
  };

  const response1 = new Response("Unauthorized", {
    status: 401,
    headers: {
      "x-github-otp": "required; app"
    }
  });
  const response2 = new Response("Unauthorized", {
    status: 401,
    headers: {
      "x-github-otp": "required; app"
    }
  });

  const auth = createBasicAuth({
    username: "octocat",
    password: "secret",
    async on2Fa() {
      return "123456";
    },
    request: request.defaults({
      headers: {
        "user-agent": "test"
      },
      request: {
        fetch: fetchMock
          .sandbox()
          .postOnce(matcher1, response1)
          .postOnce(matcher2, response2)
      }
    })
  });

  try {
    await auth();
    throw new Error("should not resolve");
  } catch (error) {
    expect(error.message).toMatch(/Invalid TOTP/i);
  }
});

test("empty token options", async () => {
  const auth = createBasicAuth({
    username: "octocat",
    password: "secret",
    token: {},
    async on2Fa() {
      throw new Error("Should not ask for 2FA code");
    },
    request: request.defaults({
      headers: {
        "user-agent": "test"
      },
      request: {
        fetch: fetchMock
          .sandbox()
          .postOnce("https://api.github.com/authorizations", {
            id: 123,
            token: "1234567890abcdef1234567890abcdef12345678"
          })
      }
    })
  });

  await auth();
});

test("server error", async () => {
  const auth = createBasicAuth({
    username: "octocat",
    password: "secret",
    async on2Fa() {
      throw new Error("Should not ask for 2FA code");
    },
    request: request.defaults({
      headers: {
        "user-agent": "test"
      },
      request: {
        fetch: fetchMock.sandbox().postOnce(
          "https://api.github.com/authorizations",
          new Response("Internal Server error", {
            status: 500
          })
        )
      }
    })
  });

  try {
    await auth();
    throw new Error("auth() should not resolve");
  } catch (error) {
    expect(error).toEqual(new Error("Internal Server error"));
  }
});

test("request error", async () => {
  const auth = createBasicAuth({
    username: "octocat",
    password: "secret",
    async on2Fa() {
      throw new Error("Should not ask for 2FA code");
    },
    // @ts-ignore
    request() {
      throw new Error("Request error");
    }
  });

  try {
    await auth();
    throw new Error("auth() should not resolve");
  } catch (error) {
    expect(error).toEqual(new Error("Request error"));
  }
});

test("on2FA parameter missing", async () => {
  expect(() => {
    // @ts-ignore
    createBasicAuth({
      username: "octocat",
      password: "secret"
    });
  }).toThrow();
});

test("username parameter missing", async () => {
  expect(() => {
    // @ts-ignore
    createBasicAuth({
      password: "secret",
      on2Fa() {
        return "123456";
      }
    });
  }).toThrow();
});

test("password parameter missing", async () => {
  expect(() => {
    // @ts-ignore
    createBasicAuth({
      username: "octocat",
      on2Fa() {
        return "123456";
      }
    });
  }).toThrow();
});

test("token should be cached and not re-created", async () => {
  const matcher: MockMatcherFunction = (url, { body, headers }) => {
    expect(url).toEqual("https://api.github.com/authorizations");
    expect(JSON.parse(String(body))).toStrictEqual({
      fingerprint: "4feornbt361",
      note: "octokit 1970-01-01 4feornbt361",
      note_url: "https://github.com/octokit/auth-basic.js#readme",
      scopes: []
    });
    expect(headers).toStrictEqual({
      accept: "application/vnd.github.v3+json",
      authorization: "basic b2N0b2NhdDpzZWNyZXQ=",
      "content-type": "application/json; charset=utf-8",
      "user-agent": "test"
    });
    return true;
  };
  const responseBody = {
    id: 123,
    token: "1234567890abcdef1234567890abcdef12345678"
  };

  const mock = fetchMock.sandbox().postOnce(matcher, responseBody);

  const auth = createBasicAuth({
    username: "octocat",
    password: "secret",
    async on2Fa() {
      throw new Error("Should not ask for 2FA code");
    },
    request: request.defaults({
      headers: {
        "user-agent": "test"
      },
      request: {
        fetch: mock
      }
    })
  });

  const authentication1 = await auth();
  const authentication2 = await auth();

  expect(authentication1).toEqual(authentication2);
});

// If multiple requests are sent to endpoints which require basic authentication
// over a longer period of time, it is possible that the server requires another
// 2Fa code, in which case the `on2Fa` function is called again.
test("repeated auth.hook(request, 'GET /authorizations') with expiring 2FA code", async () => {
  const expectedRequestHeaders = {
    accept: "application/vnd.github.v3+json",
    authorization: "basic b2N0b2NhdDpzZWNyZXQ=",
    "user-agent": "test"
  };

  const matcher: MockMatcherFunction = (url, { body, headers }) => {
    expect(url).toEqual("https://api.github.com/authorizations");
    expect(headers).toStrictEqual(expectedRequestHeaders);
    return true;
  };
  const matcherWithOtp: MockMatcherFunction = (url, { body, headers }) => {
    expect(url).toEqual("https://api.github.com/authorizations");
    expect(headers).toStrictEqual({
      ...expectedRequestHeaders,
      "x-github-otp": "123456"
    });
    return true;
  };
  const matcherWithOtp2: MockMatcherFunction = (url, { body, headers }) => {
    expect(url).toEqual("https://api.github.com/authorizations");
    expect(headers).toStrictEqual({
      ...expectedRequestHeaders,
      "x-github-otp": "654321"
    });
    return true;
  };

  const responseOtpRequired = new Response("Unauthorized", {
    status: 401,
    headers: {
      "x-github-otp": "required; app"
    }
  });
  const response = [{ id: 123 }];

  const mock = fetchMock
    .sandbox()
    .getOnce(matcher, responseOtpRequired)
    .getOnce(matcherWithOtp, response)
    .getOnce(matcherWithOtp, response)
    .getOnce(matcherWithOtp, responseOtpRequired.clone())
    .getOnce(matcherWithOtp2, response);

  const requestMock = request.defaults({
    headers: {
      "user-agent": "test"
    },
    request: {
      fetch: mock
    }
  });

  const on2FaMock = jest
    .fn()
    .mockReturnValueOnce("123456")
    .mockReturnValueOnce("654321");

  const { hook } = createBasicAuth({
    username: "octocat",
    password: "secret",
    on2Fa: on2FaMock
  });

  const { status: status1, data: data1 } = await hook(
    requestMock,
    "GET /authorizations"
  );
  const { status: status2, data: data2 } = await hook(
    requestMock,
    "GET /authorizations"
  );
  const { status: status3, data: data3 } = await hook(
    requestMock,
    "GET /authorizations"
  );

  expect(status1).toEqual(200);
  expect(data1).toStrictEqual(response);
  expect(status2).toEqual(200);
  expect(data2).toStrictEqual(response);
  expect(status3).toEqual(200);
  expect(data3).toStrictEqual(response);

  expect(mock.done()).toBeTruthy();

  // test that TOTP is cached and not re-requested until
  // a 401 error
  expect(on2FaMock.mock.calls.length).toEqual(2);
});

test('auth({type: "basic"}) with 500 server error', async () => {
  const requestMock = request.defaults({
    headers: {
      "user-agent": "test"
    },
    request: {
      fetch: fetchMock.sandbox().patchOnce(
        "https://api.github.com/authorizations",
        new Response("Oops", {
          status: 500
        })
      )
    }
  });

  const auth = createBasicAuth({
    username: "octocat",
    password: "secret",
    async on2Fa() {
      return "123456";
    },

    request: requestMock
  });

  try {
    await auth({ type: "basic" });
  } catch (error) {
    expect(error.status).toEqual(500);
  }
});
test('auth.hook(request, "GET /user") with 2Fa', async () => {
  const expectedCreateTokenRequestHeaders = {
    accept: "application/vnd.github.v3+json",
    authorization: "basic b2N0b2NhdDpzZWNyZXQ=",
    "content-type": "application/json; charset=utf-8",
    "user-agent": "test"
  };

  const matchCreateToken: MockMatcherFunction = (url, { body, headers }) => {
    expect(url).toEqual("https://api.github.com/authorizations");
    expect(JSON.parse(String(body))).toStrictEqual({
      fingerprint: "4feornbt361",
      note: "octokit 1970-01-01 4feornbt361",
      note_url: "https://github.com/octokit/auth-basic.js#readme",
      scopes: []
    });
    expect(headers).toStrictEqual(expectedCreateTokenRequestHeaders);

    return true;
  };

  const matchCreateTokenWithOtp: MockMatcherFunction = (
    url,
    { body, headers }
  ) => {
    expect(url).toEqual("https://api.github.com/authorizations");
    expect(JSON.parse(String(body))).toStrictEqual({
      fingerprint: "4feornbt361",
      note: "octokit 1970-01-01 4feornbt361",
      note_url: "https://github.com/octokit/auth-basic.js#readme",
      scopes: []
    });
    expect(headers).toStrictEqual({
      ...expectedCreateTokenRequestHeaders,
      "x-github-otp": "123456"
    });

    return true;
  };

  const matchGetUserWithOtp: MockMatcherFunction = (url, { body, headers }) => {
    expect(url).toEqual("https://api.github.com/user");
    expect(headers).toStrictEqual({
      accept: "application/vnd.github.v3+json",
      authorization: "token 1234567890abcdef1234567890abcdef12345678",
      "user-agent": "test"
    });

    return true;
  };

  const responseGetUser = {
    id: 1
  };
  const responseTokenCreated = {
    id: 123,
    token: "1234567890abcdef1234567890abcdef12345678"
  };
  const responseOtpRequired = new Response("Unauthorized", {
    status: 401,
    headers: {
      "x-github-otp": "required; app"
    }
  });

  const mock = fetchMock
    .sandbox()
    .postOnce(matchCreateToken, responseOtpRequired)
    .postOnce(matchCreateTokenWithOtp, responseTokenCreated)
    .getOnce(matchGetUserWithOtp, responseGetUser);

  const requestMock = request.defaults({
    headers: {
      "user-agent": "test"
    },
    request: {
      fetch: mock
    }
  });

  const { hook } = createBasicAuth({
    username: "octocat",
    password: "secret",
    on2Fa: () => `123456`
  });

  const { data } = await hook(requestMock, "GET /user");

  expect(data).toStrictEqual({ id: 1 });

  expect(mock.done()).toBeTruthy();
});

test('auth.hook(request, "GET /authorizations") with 2Fa & SMS delivery', async () => {
  const expectedRequestHeaders = {
    accept: "application/vnd.github.v3+json",
    authorization: "basic b2N0b2NhdDpzZWNyZXQ=",
    "user-agent": "test"
  };

  const matchGetAuthorizations: MockMatcherFunction = (
    url,
    { body, headers }
  ) => {
    expect(url).toEqual("https://api.github.com/authorizations");
    expect(headers).toStrictEqual(expectedRequestHeaders);
    return true;
  };

  const matchPatchAuthorizations: MockMatcherFunction = (
    url,
    { body, headers }
  ) => {
    expect(url).toEqual("https://api.github.com/authorizations");
    expect(headers).toStrictEqual({
      ...expectedRequestHeaders,
      "content-length": 0
    });
    return true;
  };

  const matchGetAuthorizationsWithOtp: MockMatcherFunction = (
    url,
    { body, headers }
  ) => {
    expect(url).toEqual("https://api.github.com/authorizations");
    expect(headers).toStrictEqual({
      ...expectedRequestHeaders,
      "x-github-otp": "123456"
    });
    return true;
  };

  const responseOtpRequired = new Response("Unauthorized", {
    status: 401,
    headers: {
      "x-github-otp": "required; sms"
    }
  });
  const response = [{ id: 123 }];

  const mock = fetchMock
    .sandbox()
    .getOnce(matchGetAuthorizations, responseOtpRequired)
    .patchOnce(matchPatchAuthorizations, responseOtpRequired.clone())
    .getOnce(matchGetAuthorizationsWithOtp, response);

  const requestMock = request.defaults({
    headers: {
      "user-agent": "test"
    },
    request: {
      fetch: mock
    }
  });

  const { hook } = createBasicAuth({
    username: "octocat",
    password: "secret",
    on2Fa: () => "123456"
  });

  const { data } = await hook(requestMock, "GET /authorizations");

  expect(data).toStrictEqual(response);

  expect(mock.calls().length).toBe(3);
});
test('auth.hook(request, "GET /authorizations") with 500 error on SMS delivery trigger request', async () => {
  const mock = fetchMock
    .sandbox()
    .getOnce(
      "https://api.github.com/authorizations",
      new Response("Unauthorized", {
        status: 401,
        headers: {
          "x-github-otp": "required; sms"
        }
      })
    )
    .patchOnce(
      "https://api.github.com/authorizations",
      new Response("Oops", {
        status: 500
      })
    );

  const requestMock = request.defaults({
    headers: {
      "user-agent": "test"
    },
    request: {
      fetch: mock
    }
  });

  const { hook } = createBasicAuth({
    username: "octocat",
    password: "secret",
    on2Fa: () => "123456"
  });

  try {
    await hook(requestMock, "GET /authorizations");
  } catch (error) {
    expect(error.status).toEqual(500);
  }
});
test('auth({type:"basic"}) with 500 on TOTP-authenticated request', async () => {
  const requestMock = request.defaults({
    headers: {
      "user-agent": "test"
    },
    request: {
      fetch: fetchMock
        .sandbox()
        .patchOnce(
          "https://api.github.com/authorizations",
          new Response("Unauthorized", {
            status: 401,
            headers: {
              "x-github-otp": "required; app"
            }
          })
        )
        .patchOnce(
          "https://api.github.com/authorizations",
          new Response("Oops", {
            status: 500
          })
        )
    }
  });

  const auth = createBasicAuth({
    username: "octocat",
    password: "secret",
    async on2Fa() {
      return "123456";
    },

    request: requestMock
  });

  try {
    await auth({ type: "basic" });
  } catch (error) {
    expect(error.status).toEqual(500);
  }
});

test('auth({type:"token"}) with custom token settings', async () => {
  const matcher: MockMatcherFunction = (url, { body, headers }) => {
    expect(url).toEqual("https://api.github.com/authorizations");
    expect(JSON.parse(String(body))).toStrictEqual({
      fingerprint: "fingerprint",
      note: "My custom note",
      note_url: "https://example.com/my-custom-token-note-url",
      scopes: ["repo", "notifications"],
      client_id: "01234567890123456789",
      client_secret: "0123456789012345678901234567890123456789"
    });
    return true;
  };
  const responseBody = {
    id: 123,
    token: "1234567890abcdef1234567890abcdef12345678"
  };

  const mock = fetchMock.sandbox().postOnce(matcher, responseBody);

  const auth = createBasicAuth({
    username: "octocat",
    password: "secret",
    async on2Fa() {
      throw new Error("Should not ask for 2FA code");
    },
    token: {
      note: "My custom note",
      scopes: ["repo", "notifications"],
      noteUrl: "https://example.com/my-custom-token-note-url",
      fingerprint: "fingerprint",
      clientId: "01234567890123456789",
      clientSecret: "0123456789012345678901234567890123456789"
    },
    request: request.defaults({
      headers: {
        "user-agent": "test"
      },
      request: {
        fetch: mock
      }
    })
  });

  const authentication = await auth();

  expect(authentication).toEqual({
    type: "token",
    token: "1234567890abcdef1234567890abcdef12345678",
    tokenType: "oauth",
    id: 123,
    username: "octocat"
  });
});

test('auth({type:"token"}) with token note conflict', async () => {
  const matcher: MockMatcherFunction = (url, { body, headers }) => {
    expect(url).toEqual("https://api.github.com/authorizations");
    expect(JSON.parse(String(body))).toStrictEqual({
      fingerprint: "fingerprint",
      note: "My custom note",
      note_url: "https://example.com/my-custom-token-note-url",
      scopes: ["repo", "notifications"],
      client_id: "01234567890123456789",
      client_secret: "0123456789012345678901234567890123456789"
    });
    return true;
  };
  const responseBody = {
    id: 123,
    token: "1234567890abcdef1234567890abcdef12345678"
  };

  const mock = fetchMock.sandbox().postOnce(
    "https://api.github.com/authorizations",
    new Response("Validation Failed", {
      status: 422
    })
  );

  const auth = createBasicAuth({
    username: "octocat",
    password: "secret",
    async on2Fa() {
      throw new Error("Should not ask for 2FA code");
    },
    token: {
      note: "My custom note",
      fingerprint: "fingerprint"
    },
    request: request.defaults({
      headers: {
        "user-agent": "test"
      },
      request: {
        fetch: mock
      }
    })
  });

  try {
    const authentication = await auth();
    throw new Error("Should not resolve");
  } catch (error) {
    expect(error.status).toBe(422);
  }
});

test('auth({type:"token", refresh: true})', async () => {
  const matcher1: MockMatcherFunction = (url, { body, headers }) => {
    expect(url).toEqual("https://api.github.com/authorizations");
    expect(JSON.parse(String(body)).fingerprint).toBe("4feornbt361");
    return true;
  };
  const responseBody1 = {
    id: 123,
    token: "1234567890abcdef1234567890abcdef12345678"
  };

  const matcher2: MockMatcherFunction = (url, { body, headers }) => {
    expect(url).toEqual("https://api.github.com/authorizations");
    expect(JSON.parse(String(body)).fingerprint).toBe("gez4w97rxp");
    return true;
  };
  const responseBody2 = {
    id: 456,
    token: "87654321fedcba0987654321fedcba0987654321"
  };

  const mock = fetchMock
    .sandbox()
    .postOnce(matcher1, responseBody1)
    .postOnce(matcher2, responseBody2);

  const auth = createBasicAuth({
    username: "octocat",
    password: "secret",
    async on2Fa() {
      throw new Error("Should not ask for 2FA code");
    },
    request: request.defaults({
      headers: {
        "user-agent": "test"
      },
      request: {
        fetch: mock
      }
    })
  });

  const authentication1 = (await auth({
    type: "token"
  })) as TokenAuthentication;

  Math.random = jest.fn().mockReturnValue(0.456);
  // < Math.random().toString(36).substr(2)
  // > gez4w97rxp

  const authentication2 = (await auth({
    type: "token",
    refresh: true
  })) as TokenAuthentication;

  expect(authentication1.token).toEqual(
    "1234567890abcdef1234567890abcdef12345678"
  );
  expect(authentication2.token).toEqual(
    "87654321fedcba0987654321fedcba0987654321"
  );
});

// should not send a "PATCH /authorizations" request as "PATCH /authorizations/123"
// triggers SMS delivery, too.
test('auth.hook(request, "PATCH /authorizations/123") with 2Fa & SMS delivery', async () => {
  const expectedRequestHeaders = {
    accept: "application/vnd.github.v3+json",
    authorization: "basic b2N0b2NhdDpzZWNyZXQ=",
    "content-type": "application/json; charset=utf-8",
    "user-agent": "test"
  };

  const matchPatchAuthorization: MockMatcherFunction = (
    url,
    { body, headers }
  ) => {
    expect(url).toEqual("https://api.github.com/authorizations/123");
    expect(headers).toStrictEqual(expectedRequestHeaders);
    return true;
  };

  const matchPatchAuthorizationWithOtp: MockMatcherFunction = (
    url,
    { body, headers }
  ) => {
    expect(url).toEqual("https://api.github.com/authorizations/123");
    expect(headers).toStrictEqual({
      ...expectedRequestHeaders,
      "x-github-otp": "123456"
    });
    return true;
  };

  const responseOtpRequired = new Response("Unauthorized", {
    status: 401,
    headers: {
      "x-github-otp": "required; sms"
    }
  });
  const response = [{ id: 123 }];

  const mock = fetchMock
    .sandbox()
    .patchOnce(matchPatchAuthorization, responseOtpRequired)
    .patchOnce(matchPatchAuthorizationWithOtp, response);

  const requestMock = request.defaults({
    headers: {
      "user-agent": "test"
    },
    request: {
      fetch: mock
    }
  });

  const { hook } = createBasicAuth({
    username: "octocat",
    password: "secret",
    on2Fa: () => "123456"
  });

  const { data } = await hook(requestMock, "PATCH /authorizations/123", {
    add_scopes: ["repo"]
  });

  expect(data).toStrictEqual(response);

  expect(mock.calls().length).toBe(2);
});

test("If token.note is set, do not default fingerprint to a random string to avoid multiple tokens with the same note", async () => {
  const matcher: MockMatcherFunction = (url, { body, headers }) => {
    expect(url).toEqual("https://api.github.com/authorizations");
    expect(JSON.parse(String(body))).toStrictEqual({
      note: "My custom note",
      note_url: "https://github.com/octokit/auth-basic.js#readme",
      scopes: []
    });
    return true;
  };
  const responseBody = {
    id: 123,
    token: "1234567890abcdef1234567890abcdef12345678"
  };

  const mock = fetchMock.sandbox().postOnce(matcher, responseBody);

  const auth = createBasicAuth({
    username: "octocat",
    password: "secret",
    async on2Fa() {
      throw new Error("Should not ask for 2FA code");
    },
    token: {
      note: "My custom note"
    },
    request: request.defaults({
      headers: {
        "user-agent": "test"
      },
      request: {
        fetch: mock
      }
    })
  });

  const authentication = await auth();

  expect(authentication).toEqual({
    type: "token",
    token: "1234567890abcdef1234567890abcdef12345678",
    tokenType: "oauth",
    id: 123,
    username: "octocat"
  });
});
