import { Elysia } from "elysia";
import oauth2, { google } from "@bogeychan/elysia-oauth2";
import { swagger } from "@elysiajs/swagger";

import { randomBytes } from "crypto";
import { Database } from "bun:sqlite";

const db = new Database(":memory:");

db.run("CREATE TABLE IF NOT EXISTS users(username TEXT);");
db.run("INSERT INTO users (username) VALUES ('john'), ('harry'), ('chad');");

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

function redirectNotLogin(ctx) {
  console.log("user not logged in. redirecting");

  ctx.set.redirect = "/";
}

app
  .use(auth)
  .use(swagger())
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
  .get("/users", async (ctx) => {
    if (await ctx.authorized("google")) {
      const data = db.query("SELECT * FROM users;").all();
      return data;
    }

    return redirectNotLogin(ctx);
  })
  .get("/users/add/:name", async (ctx) => {
    if (await ctx.authorized("google")) {
      db.run("INSERT INTO users (username) VALUES (?);", [ctx.params.name]);
      ctx.set.redirect = "/users";
      return;
    }
    return redirectNotLogin(ctx);
  })
  .get("/users/remove/:name", async (ctx) => {
    if (await ctx.authorized("google")) {
      db.run("DELETE FROM users WHERE username=?", [ctx.params.name]);
      ctx.set.redirect = "/users";
      return;
    }
    return redirectNotLogin(ctx);
  })
  .listen(3000);

console.log("Listening on http://localhost:3000");