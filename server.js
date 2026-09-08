const express = require("express");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const CLIENT_ID = process.env.SHOPIFY_CLIENT_ID;
const CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;

const SCOPES = "write_products";

// Tijdelijke opslag voor OAuth-states en tokens.
// We maken dit later permanent.
const states = new Map();
const tokens = new Map();

function validShop(shop) {
  return typeof shop === "string" &&
    /^[a-zA-Z0-9][a-zA-Z0-9-]*\.myshopify\.com$/.test(shop);
}

function verifyHmac(query) {
  const { hmac, ...params } = query;

  if (!hmac) return false;

  const message = Object.keys(params)
    .sort()
    .map((key) => `${key}=${params[key]}`)
    .join("&");

  const digest = crypto
    .createHmac("sha256", CLIENT_SECRET)
    .update(message)
    .digest("hex");

  try {
    return crypto.timingSafeEqual(
      Buffer.from(digest, "utf8"),
      Buffer.from(hmac, "utf8")
    );
  } catch {
    return false;
  }
}

// Startpagina
app.get("/", (req, res) => {
  res.send(`
    <h1>Maison Lévara Paris</h1>
    <p>Shopify API connection is online.</p>
  `);
});

// Shopify installatie starten
app.get("/auth", (req, res) => {
  const shop = req.query.shop;

  if (!validShop(shop)) {
    return res.status(400).send(
      "Ongeldige Shopify shop. Gebruik bijvoorbeeld jouw-winkel.myshopify.com"
    );
  }

  const state = crypto.randomBytes(16).toString("hex");
  states.set(state, shop);

  const authUrl =
    `https://${shop}/admin/oauth/authorize?` +
    new URLSearchParams({
      client_id: CLIENT_ID,
      scope: SCOPES,
      redirect_uri: REDIRECT_URI,
      state: state
    }).toString();

  res.redirect(authUrl);
});

// Shopify stuurt de gebruiker hier terug
app.get("/auth/callback", async (req, res) => {
  const { code, shop, state } = req.query;

  if (!validShop(shop)) {
    return res.status(400).send("Ongeldige Shopify shop.");
  }

  if (!state || states.get(state) !== shop) {
    return res.status(403).send("Ongeldige state.");
  }

  states.delete(state);

  if (!verifyHmac(req.query)) {
    return res.status(403).send("Ongeldige Shopify HMAC.");
  }

  try {
    const response = await fetch(
      `https://${shop}/admin/oauth/access_token`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
          code: code
        })
      }
    );

    const data = await response.json();

    if (!response.ok) {
      console.error(data);
      return res.status(500).send("Shopify token-uitwisseling mislukt.");
    }

    tokens.set(shop, {
      accessToken: data.access_token,
      scope: data.scope
    });

    res.send(`
      <h1>Shopify succesvol verbonden!</h1>
      <p>Maison Lévara Paris is verbonden met Shopify.</p>
      <p>Shop: ${shop}</p>
      <p>Scope: ${data.scope}</p>
      <p>De API-verbinding werkt.</p>
    `);

  } catch (error) {
    console.error(error);
    res.status(500).send("Er ging iets mis met de verbinding met Shopify.");
  }
});

// Eenvoudige test om producten op te halen
app.get("/products", async (req, res) => {
  const shop = req.query.shop;

  if (!validShop(shop)) {
    return res.status(400).send("Ongeldige Shopify shop.");
  }

  const connection = tokens.get(shop);

  if (!connection) {
    return res.status(401).send(
      "Shopify is nog niet verbonden. Gebruik eerst /auth?shop=..."
    );
  }

  const query = `
    query {
      products(first: 10) {
        nodes {
          id
          title
          handle
        }
      }
    }
  `;

  try {
    const response = await fetch(
      `https://${shop}/admin/api/2026-07/graphql.json`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Shopify-Access-Token": connection.accessToken
        },
        body: JSON.stringify({ query })
      }
    );

    const data = await response.json();

    res.json(data);

  } catch (error) {
    console.error(error);
    res.status(500).send("Producten konden niet worden opgehaald.");
  }
});

app.listen(PORT, () => {
  console.log(`Maison Lévara Shopify API running on port ${PORT}`);
});
