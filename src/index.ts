import { Elysia } from "elysia";
import oauth2, { google } from "@bogeychan/elysia-oauth2";

import { randomBytes } from "crypto";

const globalState = randomBytes(8).toString("hex");
let globalToken = null;

const app = new Elysia();

const auth = oauth2({
  profiles: {
    // define multiple OAuth 2.0 profiles
    google: {
      provider: google(),
      scope: ["https://www.googleapis.com/auth/userinfo.profile"],
    },
  },
  state: {
    // custom state verification between requests
    check(ctx, name, state) {
      return state === globalState;
    },
    generate(ctx, name) {
      return globalState;
    },
  },
  storage: {
    // storage of users' access tokens is up to you
    get(ctx, name) {
      return globalToken;
    },
    set(ctx, name, token) {
      globalToken = token;
    },
    delete(ctx, name) {
      globalToken = null;
    },
  },
});

function userPage(user: {}, logout: string) {
  const html = `<!DOCTYPE html>
    <html lang="en">
    <body>
      User:
      <pre>${JSON.stringify(user, null, "\t")}</pre>
      <a href="${logout}">Logout</a>
    </body>
    </html>`;

  return new Response(html, { headers: { "Content-Type": "text/html" } });
}

app
  .use(auth)
  .get("/", async (ctx) => {
    const profiles = ctx.profiles("google");

    if (await ctx.authorized("google")) {
      const user = await fetch(
        "https://www.googleapis.com/oauth2/v1/userinfo",
        {
          headers: await ctx.tokenHeaders("google"),
        }
      );

      return userPage(await user.json(), profiles.google.logout);
    }

    // Render login page
    const html = `<!DOCTYPE html>
    <html lang="en">
    <body>
      <h2>Login with <a href="${profiles.google.login}">Google</a></h2>
    </body>
    </html>`;

    return new Response(html, { headers: { "Content-Type": "text/html" } });
  })
  .listen(3000);

console.log("Listening on http://localhost:3000");