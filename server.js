const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const CLIENT_ID = process.env.SHOPIFY_CLIENT_ID;
const CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-5-mini";
const SHOPIFY_API_VERSION = "2026-07";
const SCOPES = "write_products";
const TOKEN_FILE =
  process.env.TOKEN_FILE ||
  path.join("/tmp", "maison-levara-tokens.json");

const oauthStates = new Map();
const sessions = new Map();

let tokens = loadTokens();

const job = {
  running: false,
  mode: null,
  shop: null,
  total: 0,
  pending: 0,
  processed: 0,
  skipped: 0,
  failed: 0,
  current: null,
  startedAt: null,
  finishedAt: null,
  logs: [],
  errors: []
};

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function validShop(shop) {
  return (
    typeof shop === "string" &&
    /^[a-zA-Z0-9][a-zA-Z0-9-]*\.myshopify\.com$/.test(shop)
  );
}

function normalize(value) {
  return String(value || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim();
}

function log(message) {
  const line = `[${new Date().toISOString()}] ${message}`;

  job.logs.push(line);

  if (job.logs.length > 300) {
    job.logs.shift();
  }

  console.log(line);
}

function parseCookies(req) {
  const out = {};

  for (
    const part of
      (req.headers.cookie || "").split(";")
  ) {
    const i = part.indexOf("=");

    if (i < 0) {
      continue;
    }

    out[
      part.slice(0, i).trim()
    ] =
      decodeURIComponent(
        part.slice(i + 1).trim()
      );
  }

  return out;
}

function setSession(res, shop) {
  const id =
    crypto.randomBytes(32).toString("hex");

  sessions.set(id, {
    shop,
    expiresAt:
      Date.now() +
      24 * 60 * 60 * 1000
  });

  res.setHeader(
    "Set-Cookie",
    `ml_session=${encodeURIComponent(
      id
    )}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`
  );
}

function getSessionShop(req) {
  const id =
    parseCookies(req).ml_session;

  if (!id) {
    return null;
  }

  const session =
    sessions.get(id);

  if (!session) {
    return null;
  }

  if (
    session.expiresAt <
    Date.now()
  ) {
    sessions.delete(id);
    return null;
  }

  return session.shop;
}

function loadTokens() {
  try {
    if (!fs.existsSync(TOKEN_FILE)) {
      return new Map();
    }

    return new Map(
      Object.entries(
        JSON.parse(
          fs.readFileSync(
            TOKEN_FILE,
            "utf8"
          )
        )
      )
    );
  } catch {
    return new Map();
  }
}

function saveTokens() {
  try {
    fs.mkdirSync(
      path.dirname(TOKEN_FILE),
      {
        recursive: true
      }
    );

    fs.writeFileSync(
      TOKEN_FILE,
      JSON.stringify(
        Object.fromEntries(tokens),
        null,
        2
      ),
      {
        mode: 0o600
      }
    );
  } catch (error) {
    log(
      `Token-opslag niet beschikbaar: ${error.message}`
    );
  }
}

function verifyHmac(query) {
  const {
    hmac,
    ...params
  } = query;

  if (
    !hmac ||
    !CLIENT_SECRET
  ) {
    return false;
  }

  const message =
    Object.keys(params)
      .sort()
      .map(
        (key) =>
          `${key}=${params[key]}`
      )
      .join("&");

  const digest =
    crypto
      .createHmac(
        "sha256",
        CLIENT_SECRET
      )
      .update(message)
      .digest("hex");

  try {
    return crypto.timingSafeEqual(
      Buffer.from(digest),
      Buffer.from(
        String(hmac)
      )
    );
  } catch {
    return false;
  }
}

/* =========================================================
   SHOPIFY GRAPHQL
========================================================= */

async function shopifyGraphQL(
  shop,
  token,
  query,
  variables = {}
) {
  let lastError = null;

  for (
    let attempt = 0;
    attempt < 6;
    attempt++
  ) {
    try {
      const response =
        await fetch(
          `https://${shop}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`,
          {
            method: "POST",

            headers: {
              "Content-Type":
                "application/json",

              "X-Shopify-Access-Token":
                token
            },

            body:
              JSON.stringify({
                query,
                variables
              })
          }
        );

      const body =
        await response.json();

      if (
        response.status ===
        429
      ) {
        lastError =
          new Error(
            "Shopify rate limit"
          );

        await sleep(
          Math.min(
            15000,
            1000 *
              2 ** attempt
          )
        );

        continue;
      }

      if (!response.ok) {
        throw new Error(
          `Shopify HTTP ${response.status}: ${JSON.stringify(
            body
          )}`
        );
      }

      if (
        body.errors?.length
      ) {
        const message =
          body.errors
            .map(
              (x) =>
                x.message
            )
            .join(" | ");

        if (
          /throttl/i.test(
            message
          )
        ) {
          lastError =
            new Error(
              message
            );

          await sleep(
            Math.min(
              15000,
              1000 *
                2 ** attempt
            )
          );

          continue;
        }

        throw new Error(
          message
        );
      }

      return body.data;
    } catch (error) {
      lastError = error;

      if (
        attempt === 5
      ) {
        break;
      }

      await sleep(
        Math.min(
          15000,
          1000 *
            2 ** attempt
        )
      );
    }
  }

  throw (
    lastError ||
    new Error(
      "Shopify API request failed"
    )
  );
}

/* =========================================================
   PRODUCT DATA
========================================================= */

const PRODUCTS_QUERY = `
  query Products($after: String) {
    products(first: 100, after: $after) {
      nodes {
        id
        title
        handle
        productType
        descriptionHtml

        seo {
          title
          description
        }

        options {
          id
          name
          position

          optionValues {
            id
            name
            hasVariants
            linkedMetafieldValue
          }
        }

        media(first: 100) {
          nodes {
            id
            alt
            mediaContentType
          }
        }

        metafields(first: 100) {
          nodes {
            id
            namespace
            key
            type
            value
          }
        }
      }

      pageInfo {
        hasNextPage
        endCursor
      }
    }
  }
`;

async function getAllProducts(
  shop,
  token
) {
  const products = [];

  let after = null;

  while (true) {
    const data =
      await shopifyGraphQL(
        shop,
        token,
        PRODUCTS_QUERY,
        {
          after
        }
      );

    products.push(
      ...data.products.nodes
    );

    if (
      !data.products
        .pageInfo
        .hasNextPage
    ) {
      break;
    }

    after =
      data.products
        .pageInfo
        .endCursor;
  }

  return products;
}

/* =========================================================
   BF SIZE CHART
   READ-ONLY DIAGNOSTIC
========================================================= */

async function getShopBFMetafield(
  shop,
  token
) {
  const query = `
    query BFSizeChart {
      shop {
        id

        metafield(
          namespace: "sizechartsrelentless"
          key: "size_charts"
        ) {
          id
          namespace
          key
          type
          value
          compareDigest
        }
      }
    }
  `;

  const data =
    await shopifyGraphQL(
      shop,
      token,
      query
    );

  return data.shop;
}

/* =========================================================
   HTML PROTECTION
========================================================= */

function protectHtml(
  html
) {
  const tags = [];
  const attrs = [];

  let source =
    String(html || "");

  source =
    source.replace(
      /<[^>]*>/g,
      (tag) => {
        let safeTag = tag;

        safeTag =
          safeTag.replace(
            /\b(alt|title)\s*=\s*(["'])([\s\S]*?)\2/gi,
            (
              full,
              name,
              quote,
              value
            ) => {
              const id =
                attrs.length;

              const token =
                `___ML_ATTR_${String(
                  id
                ).padStart(
                  5,
                  "0"
                )}___`;

              attrs.push({
                id,
                name:
                  name.toLowerCase(),
                value
              });

              return `${name}=${quote}${token}${quote}`;
            }
          );

        const token =
          `___ML_TAG_${String(
            tags.length
          ).padStart(
            5,
            "0"
          )}___`;

        tags.push({
          token,
          tag:
            safeTag
        });

        return token;
      }
    );

  return {
    html:
      source,
    tags,
    attrs
  };
}

function restoreHtml(
  translated,
  prepared,
  translatedAttrs
) {
  let html =
    String(
      translated || ""
    );

  const map =
    new Map(
      (
        translatedAttrs ||
        []
      ).map(
        (x) => [
          Number(
            x.id
          ),
          String(
            x.value || ""
          )
        ]
      )
    );

  for (
    const attr of
      prepared.attrs
  ) {
    let value =
      map.has(
        attr.id
      )
        ? map.get(
            attr.id
          )
        : attr.value;

    value =
      value
        .replace(
          /&/g,
          "&amp;"
        )
        .replace(
          /"/g,
          "&quot;"
        )
        .replace(
          /</g,
          "&lt;"
        )
        .replace(
          />/g,
          "&gt;"
        );

    const token =
      `___ML_ATTR_${String(
        attr.id
      ).padStart(
        5,
        "0"
      )}___`;

    if (
      html.split(
        token
      ).length -
        1 !==
      1
    ) {
      throw new Error(
        `HTML-attribuut ${token} ontbreekt of is dubbel.`
      );
    }

    html =
      html.replace(
        token,
        value
      );
  }

  for (
    const item of
      prepared.tags
  ) {
    if (
      html.split(
        item.token
      ).length -
        1 !==
      1
    ) {
      throw new Error(
        `HTML-tag ${item.token} ontbreekt of is dubbel.`
      );
    }

    html =
      html.replace(
        item.token,
        item.tag
      );
  }

  if (
    /___ML_(TAG|ATTR)_\d{5}___/.test(
      html
    )
  ) {
    throw new Error(
      "Onopgeloste HTML-placeholder gevonden."
    );
  }

  return html;
}

function htmlTags(
  html
) {
  return [
    ...String(
      html || ""
    ).matchAll(
      /<\s*(\/?)\s*([a-zA-Z0-9]+)/g
    )
  ].map(
    (m) =>
      `${m[1] ? "/" : ""}${m[2].toLowerCase()}`
  );
}

function htmlUrls(
  html
) {
  return [
    ...String(
      html || ""
    ).matchAll(
      /\b(?:href|src)\s*=\s*["']([^"']+)["']/gi
    )
  ]
    .map(
      (m) =>
        m[1]
    )
    .sort();
}

function sameArray(
  a,
  b
) {
  return (
    a.length ===
      b.length &&
    a.every(
      (
        value,
        index
      ) =>
        value ===
        b[index]
    )
  );
}

function assertHtmlSafe(
  before,
  after
) {
  if (
    !sameArray(
      htmlTags(
        before
      ),
      htmlTags(
        after
      )
    )
  ) {
    throw new Error(
      "HTML-structuur is gewijzigd."
    );
  }

  if (
    !sameArray(
      htmlUrls(
        before
      ),
      htmlUrls(
        after
      )
    )
  ) {
    throw new Error(
      "Een href/src URL is gewijzigd."
    );
  }
}

/* =========================================================
   FRENCH PRODUCT NAMING
========================================================= */

const FRENCH_NAMES = [
  "Adèle",
  "Agathe",
  "Agnès",
  "Alix",
  "Amélie",
  "Anaïs",
  "Angèle",
  "Angélique",
  "Anna",
  "Annabelle",
  "Anne",
  "Antoinette",
  "Apolline",
  "Ariane",
  "Aurélie",
  "Aurore",
  "Béatrice",
  "Bérénice",
  "Camille",
  "Capucine",
  "Carine",
  "Carla",
  "Caroline",
  "Céleste",
  "Céline",
  "Chantal",
  "Charlène",
  "Charlotte",
  "Chloé",
  "Claire",
  "Clara",
  "Clémence",
  "Colette",
  "Coralie",
  "Corinne",
  "Daphné",
  "Delphine",
  "Diane",
  "Élodie",
  "Élise",
  "Émilie",
  "Emma",
  "Estelle",
  "Eugénie",
  "Fanny",
  "Faustine",
  "Fleur",
  "Florence",
  "Gabrielle",
  "Gaëlle",
  "Hélène",
  "Inès",
  "Isabelle",
  "Jade",
  "Jeanne",
  "Joséphine",
  "Julie",
  "Juliette",
  "Justine",
  "Laura",
  "Laurence",
  "Léa",
  "Léna",
  "Léonie",
  "Lou",
  "Louise",
  "Lucie",
  "Madeleine",
  "Maëlle",
  "Manon",
  "Margaux",
  "Margot",
  "Marianne",
  "Marie",
  "Marion",
  "Mathilde",
  "Mélanie",
  "Mélissa",
  "Mélodie",
  "Mireille",
  "Monique",
  "Nathalie",
  "Noémie",
  "Océane",
  "Odette",
  "Pauline",
  "Perrine",
  "Rachel",
  "Raphaëlle",
  "Romane",
  "Rose",
  "Rosalie",
  "Sabine",
  "Salomé",
  "Sandrine",
  "Sarah",
  "Ségolène",
  "Sophie",
  "Solène",
  "Suzanne",
  "Sylvie",
  "Tess",
  "Valentine",
  "Valérie",
  "Vanessa",
  "Véronique",
  "Victoire",
  "Virginie",
  "Yasmine",
  "Zoé"
];

const FRENCH_KEYS =
  new Set(
    FRENCH_NAMES.map(
      normalize
    )
  );

function fallbackName(
  index,
  used
) {
  for (
    let i = 0;
    i <
    FRENCH_NAMES.length;
    i++
  ) {
    const name =
      FRENCH_NAMES[
        (index + i) %
          FRENCH_NAMES.length
      ];

    const prefix =
      normalize(name) +
      " |";

    const alreadyUsed =
      [...used].some(
        (title) =>
          normalize(
            title
          ).startsWith(
            prefix
          )
      );

    if (
      !alreadyUsed
    ) {
      return name;
    }
  }

  return FRENCH_NAMES[
    index %
      FRENCH_NAMES.length
  ];
}

/* =========================================================
   OPENAI
========================================================= */

const AI_SCHEMA = {
  type: "object",

  additionalProperties: false,

  properties: {
    firstName: {
      type: "string"
    },

    descriptor: {
      type: "string"
    },

    productType: {
      type: "string"
    },

    descriptionHtml: {
      type: "string"
    },

    seoTitle: {
      type: "string"
    },

    seoDescription: {
      type: "string"
    },

    htmlAttributes: {
      type: "array",

      items: {
        type: "object",

        additionalProperties: false,

        properties: {
          id: {
            type: "integer"
          },

          value: {
            type: "string"
          }
        },

        required: [
          "id",
          "value"
        ]
      }
    },

    options: {
      type: "array",

      items: {
        type: "object",

        additionalProperties: false,

        properties: {
          index: {
            type: "integer"
          },

          name: {
            type: "string"
          },

          values: {
            type: "array",

            items: {
              type: "object",

              additionalProperties: false,

              properties: {
                id: {
                  type: "string"
                },

                name: {
                  type: "string"
                }
              },

              required: [
                "id",
                "name"
              ]
            }
          }
        },

        required: [
          "index",
          "name",
          "values"
        ]
      }
    },

    media: {
      type: "array",

      items: {
        type: "object",

        additionalProperties: false,

        properties: {
          id: {
            type: "string"
          },

          alt: {
            type: "string"
          }
        },

        required: [
          "id",
          "alt"
        ]
      }
    }
  },

  required: [
    "firstName",
    "descriptor",
    "productType",
    "descriptionHtml",
    "seoTitle",
    "seoDescription",
    "htmlAttributes",
    "options",
    "media"
  ]
};

const SYSTEM_PROMPT = `
Je bent de vaste Franse productcopywriter van Maison Lévara Paris.

Vertaal alle klantzichtbare productinhoud naar natuurlijk, professioneel Frans.

PRODUCTNAAM:
Gebruik exact:
"Franse voornaam | Franse productomschrijving"

Gebruik alleen een echte Franse voornaam.

De descriptor moet:
- kort zijn
- natuurlijk Frans zijn
- duidelijk maken wat het product is
- passen bij een moderne Franse fashionstore

De volledige producttitel moet uniek zijn binnen de volledige catalogus.

Gebruik geen Nederlandse, Italiaanse, Engelse of Spaanse productnaam.

BESCHRIJVING:
Vertaal alle zichtbare tekst naar Frans.

Dit omvat:
- normale producttekst
- tabellen
- maattabellen
- tabelkoppen
- maatinformatie
- kleurinformatie

HTML:
De aangeleverde HTML-placeholders moeten exact blijven bestaan.

Wijzig nooit:
- href
- src
- URLs
- classes
- ids
- data-attributen
- cijfers
- percentages
- afmetingen
- eenheden
- SKU's
- productcodes
- technische codes

Voeg geen HTML-tags toe.
Verwijder geen HTML-tags.

ALT EN TITLE:
Vertaal normale klantzichtbare alt- en title-tekst naar Frans.

OPTIES:
Size -> Taille
Color -> Couleur
Colour -> Couleur
Material -> Matière

Vertaal normale kleurwaarden naar natuurlijk Frans.

Laat:
XS
S
M
L
XL
XXL
en numerieke maten intact.

One Size -> Taille unique.

PRODUCTTYPE:
Vertaal het producttype naar Frans.

SEO:
Vertaal SEO title en SEO description naar natuurlijk Frans.
Geen keyword stuffing.

MEDIA:
Vertaal alt-teksten.

Geef uitsluitend JSON conform het schema terug.
`;

function extractOutputText(
  body
) {
  if (
    typeof body.output_text ===
    "string"
  ) {
    return body.output_text;
  }

  for (
    const item of
      Array.isArray(
        body.output
      )
        ? body.output
        : []
  ) {
    for (
      const content of
        Array.isArray(
          item.content
        )
          ? item.content
          : []
    ) {
      if (
        typeof content?.text ===
        "string"
      ) {
        return content.text;
      }
    }
  }

  return "";
}

async function openAIJson(
  payload
) {
  if (
    !OPENAI_API_KEY
  ) {
    throw new Error(
      "OPENAI_API_KEY ontbreekt in Render."
    );
  }

  let lastError =
    null;

  for (
    let attempt = 0;
    attempt < 5;
    attempt++
  ) {
    try {
      const controller =
        new AbortController();

      const timer =
        setTimeout(
          () =>
            controller.abort(),
          180000
        );

      let response;

      try {
        response =
          await fetch(
            "https://api.openai.com/v1/responses",
            {
              method: "POST",

              signal:
                controller.signal,

              headers: {
                "Content-Type":
                  "application/json",

                Authorization:
                  `Bearer ${OPENAI_API_KEY}`
              },

              body:
                JSON.stringify({
                  model:
                    OPENAI_MODEL,

                  store:
                    false,

                  input: [
                    {
                      role:
                        "system",

                      content: [
                        {
                          type:
                            "input_text",

                          text:
                            SYSTEM_PROMPT
                        }
                      ]
                    },

                    {
                      role:
                        "user",

                      content: [
                        {
                          type:
                            "input_text",

                          text:
                            JSON.stringify(
                              payload
                            )
                        }
                      ]
                    }
                  ],

                  text: {
                    format: {
                      type:
                        "json_schema",

                      name:
                        "maison_levara_product_translation",

                      strict:
                        true,

                      schema:
                        AI_SCHEMA
                    }
                  }
                })
            }
          );
      } finally {
        clearTimeout(
          timer
        );
      }

      const body =
        await response.json();

      if (
        response.status ===
        429
      ) {
        lastError =
          new Error(
            "OpenAI rate limit"
          );

        await sleep(
          Math.min(
            20000,
            1500 *
              2 ** attempt
          )
        );

        continue;
      }

      if (
        !response.ok
      ) {
        throw new Error(
          `OpenAI HTTP ${response.status}: ${JSON.stringify(
            body
          )}`
        );
      }

      const text =
        extractOutputText(
          body
        );

      if (!text) {
        throw new Error(
          "OpenAI gaf geen output terug."
        );
      }

      return JSON.parse(
        text
      );
    } catch (error) {
      lastError =
        error;

      if (
        attempt === 4
      ) {
        break;
      }

      await sleep(
        Math.min(
          20000,
          1500 *
            2 ** attempt
        )
      );
    }
  }

  throw (
    lastError ||
    new Error(
      "OpenAI request mislukt."
    )
  );
}

async function translateProduct(
  product,
  reservedTitles,
  index
) {
  const prepared =
    protectHtml(
      product.descriptionHtml ||
        ""
    );

  const payload = {
    currentTitle:
      product.title,

    currentProductType:
      product.productType ||
      "",

    descriptionHtml:
      prepared.html,

    htmlAttributes:
      prepared.attrs,

    seo:
      product.seo || {
        title: "",
        description: ""
      },

    options:
      product.options.map(
        (
          option,
          optionIndex
        ) => ({
          index:
            optionIndex,

          id:
            option.id,

          name:
            option.name,

          values:
            option.optionValues.map(
              (value) => ({
                id:
                  value.id,

                name:
                  value.name
              })
            )
        })
      ),

    media:
      product.media.nodes.map(
        (item) => ({
          id:
            item.id,

          alt:
            item.alt ||
            ""
        })
      ),

    existingTitles:
      [
        ...reservedTitles
      ].slice(
        0,
        200
      )
  };

  for (
    let attempt = 0;
    attempt < 6;
    attempt++
  ) {
    if (
      attempt
    ) {
      payload.retry =
        `De vorige titel "${payload.previousTitle}" was al bezet. Kies beslist een andere Franse productnaam.`;
    }

    const result =
      await openAIJson(
        payload
      );

    let firstName =
      String(
        result.firstName ||
          ""
      ).trim();

    if (
      !FRENCH_KEYS.has(
        normalize(
          firstName
        )
      )
    ) {
      firstName =
        fallbackName(
          index +
            attempt,
          reservedTitles
        );
    }

    const descriptor =
      String(
        result.descriptor ||
          ""
      )
        .replace(
          /\|/g,
          " "
        )
        .trim();

    const title =
      `${firstName} | ${descriptor}`.trim();

    const key =
      normalize(
        title
      );

    payload.previousTitle =
      title;

    if (
      !descriptor ||
      !title.includes(
        "|"
      ) ||
      reservedTitles.has(
        key
      )
    ) {
      continue;
    }

    const descriptionHtml =
      restoreHtml(
        result.descriptionHtml,
        prepared,
        result.htmlAttributes
      );

    assertHtmlSafe(
      product.descriptionHtml ||
        "",
      descriptionHtml
    );

    reservedTitles.add(
      key
    );

    return {
      title,

      productType:
        String(
          result.productType ||
            ""
        ).trim(),

      descriptionHtml,

      seoTitle:
        String(
          result.seoTitle ||
            ""
        ).trim(),

      seoDescription:
        String(
          result.seoDescription ||
            ""
        ).trim(),

      options:
        Array.isArray(
          result.options
        )
          ? result.options
          : [],

      media:
        Array.isArray(
          result.media
        )
          ? result.media
          : []
    };
  }

  throw new Error(
    `Geen unieke Franse productnaam voor ${product.title}`
  );
}

/* =========================================================
   PRODUCT UPDATES
========================================================= */

async function updateProduct(
  shop,
  token,
  product,
  translated
) {
  const mutation = `
    mutation UpdateProduct(
      $product: ProductUpdateInput!
    ) {
      productUpdate(
        product: $product
      ) {
        userErrors {
          field
          message
          code
        }

        product {
          id
          title
          productType
          handle
        }
      }
    }
  `;

  const data =
    await shopifyGraphQL(
      shop,
      token,
      mutation,
      {
        product: {
          id:
            product.id,

          title:
            translated.title,

          productType:
            translated.productType ||
            product.productType,

          descriptionHtml:
            translated.descriptionHtml,

          seo: {
            title:
              translated.seoTitle,

            description:
              translated.seoDescription
          }
        }
      }
    );

  const errors =
    data.productUpdate
      .userErrors || [];

  if (
    errors.length
  ) {
    throw new Error(
      errors
        .map(
          (e) =>
            e.message
        )
        .join(" | ")
    );
  }
}

async function updateOptions(
  shop,
  token,
  product,
  translated
) {
  for (
    const option of
      product.options
  ) {
    const translatedOption =
      translated.options.find(
        (x) =>
          Number(
            x.index
          ) ===
          Number(
            option.position -
              1
          )
      );

    if (
      !translatedOption
    ) {
      continue;
    }

    const optionValuesToUpdate =
      option.optionValues
        .map(
          (original) => {
            const match =
              (
                translatedOption.values ||
                []
              ).find(
                (value) =>
                  String(
                    value.id
                  ) ===
                  String(
                    original.id
                  )
              );

            if (!match) {
              return null;
            }

            const name =
              String(
                match.name ||
                  ""
              ).trim();

            if (
              !name ||
              name ===
                original.name.trim()
            ) {
              return null;
            }

            return {
              id:
                original.id,

              name
            };
          }
        )
        .filter(
          Boolean
        );

    const name =
      String(
        translatedOption.name ||
          ""
      ).trim();

    const nameChanged =
      name &&
      name !==
        option.name.trim();

    if (
      !nameChanged &&
      !optionValuesToUpdate.length
    ) {
      continue;
    }

    const mutation = `
      mutation UpdateOption(
        $productId: ID!,
        $option: OptionUpdateInput!,
        $optionValuesToUpdate: [OptionValueUpdateInput!]
      ) {
        productOptionUpdate(
          productId: $productId,
          option: $option,
          optionValuesToUpdate: $optionValuesToUpdate
        ) {
          userErrors {
            field
            message
            code
          }

          product {
            id
          }
        }
      }
    `;

    const data =
      await shopifyGraphQL(
        shop,
        token,
        mutation,
        {
          productId:
            product.id,

          option: {
            id:
              option.id,

            name:
              name ||
              option.name,

            position:
              option.position
          },

          optionValuesToUpdate
        }
      );

    const errors =
      data
        .productOptionUpdate
        .userErrors || [];

    if (
      errors.length
    ) {
      throw new Error(
        errors
          .map(
            (e) =>
              e.message
          )
          .join(" | ")
      );
    }
  }
}

async function updateMedia(
  shop,
  token,
  product,
  translated
) {
  const media =
    translated.media
      .filter(
        (x) =>
          x.id &&
          typeof x.alt ===
            "string"
      )
      .map(
        (x) => ({
          id:
            x.id,

          alt:
            x.alt
        })
      )
      .filter(
        (x) => {
          const original =
            product.media.nodes.find(
              (m) =>
                m.id ===
                x.id
            );

          return (
            original &&
            String(
              original.alt ||
                ""
            ) !==
              x.alt
          );
        }
      );

  if (
    !media.length
  ) {
    return;
  }

  const mutation = `
    mutation UpdateMedia(
      $productId: ID!,
      $media: [UpdateMediaInput!]!
    ) {
      productUpdateMedia(
        productId: $productId,
        media: $media
      ) {
        media {
          id
          alt
        }

        mediaUserErrors {
          field
          message
          code
        }
      }
    }
  `;

  const data =
    await shopifyGraphQL(
      shop,
      token,
      mutation,
      {
        productId:
          product.id,

        media
      }
    );

  const errors =
    data
      .productUpdateMedia
      .mediaUserErrors || [];

  if (
    errors.length
  ) {
    throw new Error(
      errors
        .map(
          (e) =>
            e.message
        )
        .join(" | ")
    );
  }
}

async function markDone(
  shop,
  token,
  productId
) {
  const mutation = `
    mutation MarkDone(
      $metafields: [MetafieldsSetInput!]!
    ) {
      metafieldsSet(
        metafields: $metafields
      ) {
        userErrors {
          field
          message
          code
        }
      }
    }
  `;

  const data =
    await shopifyGraphQL(
      shop,
      token,
      mutation,
      {
        metafields: [
          {
            ownerId:
              productId,

            namespace:
              "maison_levara",

            key:
              "fr_translation_v1",

            type:
              "single_line_text_field",

            value:
              "done"
          }
        ]
      }
    );

  const errors =
    data
      .metafieldsSet
      .userErrors || [];

  if (
    errors.length
  ) {
    throw new Error(
      errors
        .map(
          (e) =>
            e.message
        )
        .join(" | ")
    );
  }
}

function isDone(
  product
) {
  return product.metafields.nodes.some(
    (x) =>
      x.namespace ===
        "maison_levara" &&
      x.key ===
        "fr_translation_v1" &&
      x.value ===
        "done"
  );
}

async function processProduct(
  shop,
  token,
  product,
  reservedTitles,
  index
) {
  const translated =
    await translateProduct(
      product,
      reservedTitles,
      index
    );

  log(
    `${product.title} -> ${translated.title}`
  );

  await updateProduct(
    shop,
    token,
    product,
    translated
  );

  await updateOptions(
    shop,
    token,
    product,
    translated
  );

  await updateMedia(
    shop,
    token,
    product,
    translated
  );

  await markDone(
    shop,
    token,
    product.id
  );

  return translated;
}

/* =========================================================
   JOBS
========================================================= */

async function runTestOne(
  shop
) {
  const connection =
    tokens.get(
      shop
    );

  if (!connection) {
    throw new Error(
      "Shopify-token ontbreekt."
    );
  }

  const products =
    await getAllProducts(
      shop,
      connection.accessToken
    );

  const product =
    products.find(
      (p) =>
        !isDone(p)
    );

  if (!product) {
    throw new Error(
      "Geen onvertaald product gevonden."
    );
  }

  const reservedTitles =
    new Set(
      products.map(
        (p) =>
          normalize(
            p.title
          )
      )
    );

  return processProduct(
    shop,
    connection.accessToken,
    product,
    reservedTitles,
    0
  );
}

async function runFullJob(
  shop
) {
  const connection =
    tokens.get(
      shop
    );

  if (!connection) {
    throw new Error(
      "Shopify-token ontbreekt."
    );
  }

  job.running =
    true;

  job.mode =
    "full";

  job.shop =
    shop;

  job.total =
    0;

  job.pending =
    0;

  job.processed =
    0;

  job.skipped =
    0;

  job.failed =
    0;

  job.current =
    null;

  job.startedAt =
    new Date().toISOString();

  job.finishedAt =
    null;

  job.logs =
    [];

  job.errors =
    [];

  try {
    log(
      "Alle producten ophalen..."
    );

    const products =
      await getAllProducts(
        shop,
        connection.accessToken
      );

    job.total =
      products.length;

    const reservedTitles =
      new Set(
        products
          .map(
            (p) =>
              normalize(
                p.title
              )
          )
          .filter(
            Boolean
          )
      );

    const pending =
      products.filter(
        (p) =>
          !isDone(p)
      );

    job.pending =
      pending.length;

    job.skipped =
      products.length -
      pending.length;

    log(
      `${products.length} producten gevonden; ${pending.length} te verwerken.`
    );

    let cursor =
      0;

    const workerCount =
      Math.min(
        4,
        Math.max(
          1,
          pending.length
        )
      );

    async function worker(
      workerId
    ) {
      while (
        true
      ) {
        const index =
          cursor++;

        if (
          index >=
          pending.length
        ) {
          return;
        }

        const product =
          pending[index];

        job.current = {
          worker:
            workerId,

          index:
            index + 1,

          total:
            pending.length,

          title:
            product.title
        };

        try {
          await processProduct(
            shop,
            connection.accessToken,
            product,
            reservedTitles,
            index
          );

          job.processed++;

          log(
            `KLAAR ${index + 1}/${pending.length}: ${product.title}`
          );
        } catch (error) {
          job.failed++;

          const message =
            `${product.title}: ${error.message}`;

          job.errors.push(
            message
          );

          log(
            `FOUT: ${message}`
          );
        } finally {
          job.current =
            null;
        }
      }
    }

    await Promise.all(
      Array.from(
        {
          length:
            workerCount
        },
        (
          _,
          index
        ) =>
          worker(
            index + 1
          )
      )
    );

    log(
      `JOB KLAAR — verwerkt ${job.processed}, overgeslagen ${job.skipped}, fouten ${job.failed}.`
    );
  } catch (error) {
    job.failed++;

    job.errors.push(
      error.message
    );

    log(
      `JOB FOUT: ${error.message}`
    );
  } finally {
    job.running =
      false;

    job.current =
      null;

    job.finishedAt =
      new Date().toISOString();
  }
}

/* =========================================================
   BASIC ROUTES
========================================================= */

app.get(
  "/",
  (
    req,
    res
  ) => {
    res.send(
      `
      <h1>Maison Lévara Paris</h1>
      <p>Shopify API is online.</p>
      `
    );
  }
);

app.get(
  "/health",
  (
    req,
    res
  ) => {
    res.json({
      ok:
        true,

      shopifyConfigured:
        Boolean(
          CLIENT_ID &&
          CLIENT_SECRET &&
          REDIRECT_URI
        ),

      openAIConfigured:
        Boolean(
          OPENAI_API_KEY
        ),

      model:
        OPENAI_MODEL,

      apiVersion:
        SHOPIFY_API_VERSION,

      scopes:
        SCOPES
    });
  }
);

/* =========================================================
   OAUTH
========================================================= */

app.get(
  "/auth",
  (
    req,
    res
  ) => {
    const shop =
      req.query.shop;

    if (
      !validShop(shop)
    ) {
      return res
        .status(400)
        .send(
          "Ongeldige Shopify shop."
        );
    }

    if (
      !CLIENT_ID ||
      !CLIENT_SECRET ||
      !REDIRECT_URI
    ) {
      return res
        .status(500)
        .send(
          "Shopify environment variables ontbreken."
        );
    }

    const state =
      crypto
        .randomBytes(
          24
        )
        .toString(
          "hex"
        );

    oauthStates.set(
      state,
      {
        shop,

        expiresAt:
          Date.now() +
          600000
      }
    );

    const authUrl =
      `https://${shop}/admin/oauth/authorize?` +
      new URLSearchParams({
        client_id:
          CLIENT_ID,

        scope:
          SCOPES,

        redirect_uri:
          REDIRECT_URI,

        state
      }).toString();

    res.redirect(
      authUrl
    );
  }
);

app.get(
  "/auth/callback",
  async (
    req,
    res
  ) => {
    const {
      code,
      shop,
      state
    } = req.query;

    if (
      !validShop(shop)
    ) {
      return res
        .status(400)
        .send(
          "Ongeldige Shopify shop."
        );
    }

    const saved =
      oauthStates.get(
        state
      );

    oauthStates.delete(
      state
    );

    if (
      !saved ||
      saved.shop !==
        shop ||
      saved.expiresAt <
        Date.now()
    ) {
      return res
        .status(403)
        .send(
          "Ongeldige of verlopen OAuth state."
        );
    }

    if (
      !verifyHmac(
        req.query
      )
    ) {
      return res
        .status(403)
        .send(
          "Ongeldige Shopify HMAC."
        );
    }

    try {
      const response =
        await fetch(
          `https://${shop}/admin/oauth/access_token`,
          {
            method:
              "POST",

            headers: {
              "Content-Type":
                "application/x-www-form-urlencoded"
            },

            body:
              new URLSearchParams({
                client_id:
                  CLIENT_ID,

                client_secret:
                  CLIENT_SECRET,

                code
              })
          }
        );

      const data =
        await response.json();

      if (
        !response.ok ||
        !data.access_token
      ) {
        return res
          .status(500)
          .send(
            `Shopify token-uitwisseling mislukt: ${JSON.stringify(
              data
            )}`
          );
      }

      tokens.set(
        shop,
        {
          accessToken:
            data.access_token,

          scope:
            data.scope
        }
      );

      saveTokens();

      setSession(
        res,
        shop
      );

      res.send(
        `
        <h1>Shopify succesvol verbonden!</h1>

        <p>
          Shop:
          ${shop}
        </p>

        <p>
          Scope:
          ${data.scope}
        </p>

        <p>
          <a href="/admin?shop=${encodeURIComponent(
            shop
          )}">
            Open vertaalbeheer
          </a>
        </p>
        `
      );
    } catch (error) {
      res
        .status(500)
        .send(
          `Shopify verbinding mislukt: ${error.message}`
        );
    }
  }
);

/* =========================================================
   PRODUCTS READ TEST
========================================================= */

app.get(
  "/products",
  async (
    req,
    res
  ) => {
    const shop =
      req.query.shop;

    if (
      !validShop(shop)
    ) {
      return res
        .status(400)
        .send(
          "Ongeldige shop."
        );
    }

    const connection =
      tokens.get(
        shop
      );

    if (!connection) {
      return res
        .status(401)
        .send(
          "Shopify is niet verbonden."
        );
    }

    try {
      const products =
        await getAllProducts(
          shop,
          connection.accessToken
        );

      res.json({
        count:
          products.length,

        sample:
          products
            .slice(
              0,
              10
            )
            .map(
              (p) => ({
                id:
                  p.id,

                title:
                  p.title,

                productType:
                  p.productType,

                handle:
                  p.handle,

                options:
                  p.options.map(
                    (o) => ({
                      name:
                        o.name,

                      values:
                        o.optionValues.map(
                          (v) =>
                            v.name
                        )
                    })
                  ),

                mediaCount:
                  p.media.nodes
                    .length,

                metafieldCount:
                  p.metafields.nodes
                    .length,

                translated:
                  isDone(
                    p
                  )
              })
            )
      });
    } catch (error) {
      res
        .status(500)
        .json({
          error:
            error.message
        });
    }
  }
);

/* =========================================================
   BF DIAGNOSTIC
   READ-ONLY
========================================================= */

app.get(
  "/bf-diagnose",
  async (
    req,
    res
  ) => {
    const shop =
      req.query.shop;

    if (
      !validShop(shop)
    ) {
      return res
        .status(400)
        .json({
          error:
            "Ongeldige shop."
        });
    }

    const connection =
      tokens.get(
        shop
      );

    if (!connection) {
      return res
        .status(401)
        .json({
          error:
            "Shopify is niet verbonden."
        });
    }

    try {
      const shopData =
        await getShopBFMetafield(
          shop,
          connection.accessToken
        );

      const metafield =
        shopData.metafield;

      if (
        !metafield
      ) {
        return res
          .status(404)
          .json({
            found:
              false,

            message:
              "BF-metafield sizechartsrelentless.size_charts niet gevonden."
          });
      }

      let parsed =
        null;

      try {
        parsed =
          JSON.parse(
            metafield.value
          );
      } catch {
        parsed =
          null;
      }

      return res.json({
        found:
          true,

        shopId:
          shopData.id,

        id:
          metafield.id,

        namespace:
          metafield.namespace,

        key:
          metafield.key,

        type:
          metafield.type,

        compareDigest:
          metafield.compareDigest,

        json:
          parsed,

        value:
          parsed === null
            ? metafield.value
            : undefined
      });
    } catch (error) {
      console.error(
        error
      );

      return res
        .status(500)
        .json({
          error:
            error.message
        });
    }
  }
);

/* =========================================================
   ADMIN PAGE
========================================================= */

app.get(
  "/admin",
  (
    req,
    res
  ) => {
    const shop =
      req.query.shop;

    if (
      !validShop(shop)
    ) {
      return res
        .status(400)
        .send(
          "Ongeldige shop."
        );
    }

    if (
      getSessionShop(req) !==
      shop
    ) {
      return res
        .status(403)
        .send(
          "Geen geldige sessie. Open eerst /auth."
        );
    }

    res.send(
      `
<!doctype html>

<html lang="nl">

<head>

<meta charset="utf-8">

<meta
  name="viewport"
  content="width=device-width,initial-scale=1"
>

<title>
  Maison Lévara — Franse vertaling
</title>

<style>

body{
  font-family:
    Arial,
    sans-serif;

  max-width:
    1000px;

  margin:
    40px auto;

  padding:
    0 20px;

  color:
    #111;
}

.card{
  background:
    #f5f5f5;

  padding:
    20px;

  border-radius:
    10px;

  margin:
    18px 0;
}

button{
  background:
    #111;

  color:
    #fff;

  border:
    0;

  border-radius:
    7px;

  padding:
    14px 20px;

  margin:
    5px 8px 5px 0;

  cursor:
    pointer;

  font-size:
    15px;
}

button:disabled{
  opacity:
    .45;

  cursor:
    not-allowed;
}

pre{
  background:
    #111;

  color:
    #eee;

  padding:
    16px;

  border-radius:
    8px;

  white-space:
    pre-wrap;

  max-height:
    500px;

  overflow:
    auto;
}

</style>

</head>

<body>

<h1>
  Maison Lévara Paris
</h1>

<h2>
  Franse productvertaling
</h2>

<div class="card">

<p>
  <strong>Shop:</strong>
  ${shop}
</p>

<p>
  Producttitel, producttype,
  volledige beschrijving, SEO,
  opties, maten, kleuren en
  media-altteksten worden vertaald.
</p>

<p>
  <strong>Niet gewijzigd:</strong>
  prijzen, voorraad, SKU's,
  barcodes, handles,
  afbeeldingen en ID's.
</p>

<p>
  Productnaamstructuur:
  <strong>
    Franse voornaam |
    Franse productomschrijving
  </strong>
</p>

</div>

<div class="card">

<button id="test">
  Test 1 product
</button>

<button id="start">
  Start alle producten
</button>

</div>

<div
  id="status"
  class="card"
>
  Status laden...
</div>

<div class="card">

<h3>
  Log
</h3>

<pre
  id="logs"
>
Wachten...
</pre>

</div>

<script>

const shop =
  ${JSON.stringify(shop)};

const test =
  document.getElementById(
    "test"
  );

const start =
  document.getElementById(
    "start"
  );

async function refresh(){

  try{

    const response =
      await fetch(
        "/translate-status?shop=" +
        encodeURIComponent(
          shop
        )
      );

    const data =
      await response.json();

    document.getElementById(
      "status"
    ).innerHTML =

      "<strong>Status:</strong> " +
      (
        data.running
          ? "BEZIG"
          : "KLAAR"
      ) +

      "<br>Totaal: " +
      data.total +

      "<br>Te verwerken: " +
      data.pending +

      "<br>Verwerkt: " +
      data.processed +

      "<br>Overgeslagen: " +
      data.skipped +

      "<br>Fouten: " +
      data.failed +

      (
        data.current
          ? (
            "<br><br><strong>Huidig:</strong> " +
            data.current.index +
            "/" +
            data.current.total +
            " — " +
            data.current.title
          )
          : ""
      );

    document.getElementById(
      "logs"
    ).textContent =
      (
        data.logs ||
        []
      ).join(
        "\\n"
      );

    test.disabled =
      data.running;

    start.disabled =
      data.running;

  }catch(error){

    console.error(
      error
    );

  }

}

test.onclick =
  async () => {

    if(
      !confirm(
        "Eén product wordt vertaald en opgeslagen. Doorgaan?"
      )
    ){
      return;
    }

    test.disabled =
      true;

    const response =
      await fetch(
        "/translate-one",
        {
          method:
            "POST",

          headers:{
            "Content-Type":
              "application/json"
          },

          body:
            JSON.stringify({
              shop
            })
        }
      );

    const data =
      await response.json();

    if(
      !response.ok
    ){

      alert(
        data.error ||
        "Test mislukt."
      );

      test.disabled =
        false;

      return;
    }

    alert(
      "Testproduct verwerkt: " +
      data.newTitle
    );

    refresh();

  };

start.onclick =
  async () => {

    if(
      !confirm(
        "Dit start alle nog niet verwerkte producten. Doorgaan?"
      )
    ){
      return;
    }

    start.disabled =
      true;

    const response =
      await fetch(
        "/translate-all",
        {
          method:
            "POST",

          headers:{
            "Content-Type":
              "application/json"
          },

          body:
            JSON.stringify({
              shop
            })
        }
      );

    const data =
      await response.json();

    if(
      !response.ok
    ){

      alert(
        data.error ||
        "Starten mislukt."
      );

      start.disabled =
        false;

      return;
    }

    alert(
      "De volledige vertaaljob is gestart."
    );

    refresh();

  };

refresh();

setInterval(
  refresh,
  3000
);

</script>

</body>

</html>
      `
    );
  }
);

/* =========================================================
   TEST ONE PRODUCT
========================================================= */

app.post(
  "/translate-one",
  async (
    req,
    res
  ) => {
    const shop =
      req.body?.shop;

    if (
      !validShop(shop)
    ) {
      return res
        .status(400)
        .json({
          error:
            "Ongeldige shop."
        });
    }

    if (
      getSessionShop(req) !==
      shop
    ) {
      return res
        .status(403)
        .json({
          error:
            "Geen geldige sessie."
        });
    }

    if (
      job.running
    ) {
      return res
        .status(409)
        .json({
          error:
            "Er draait al een job."
        });
    }

    try {
      const translated =
        await runTestOne(
          shop
        );

      res.json({
        ok:
          true,

        newTitle:
          translated.title
      });
    } catch (error) {
      res
        .status(500)
        .json({
          error:
            error.message
        });
    }
  }
);

/* =========================================================
   START ALL PRODUCTS
========================================================= */

app.post(
  "/translate-all",
  (
    req,
    res
  ) => {
    const shop =
      req.body?.shop;

    if (
      !validShop(shop)
    ) {
      return res
        .status(400)
        .json({
          error:
            "Ongeldige shop."
        });
    }

    if (
      getSessionShop(req) !==
      shop
    ) {
      return res
        .status(403)
        .json({
          error:
            "Geen geldige sessie."
        });
    }

    if (
      job.running
    ) {
      return res
        .status(409)
        .json({
          error:
            "Er draait al een job."
        });
    }

    if (
      !tokens.has(
        shop
      )
    ) {
      return res
        .status(401)
        .json({
          error:
            "Shopify-token ontbreekt."
        });
    }

    if (
      !OPENAI_API_KEY
    ) {
      return res
        .status(500)
        .json({
          error:
            "OPENAI_API_KEY ontbreekt."
        });
    }

    runFullJob(
      shop
    ).catch(
      (error) => {
        log(
          `Onverwachte job-fout: ${error.message}`
        );
      }
    );

    res
      .status(202)
      .json({
        ok:
          true
      });
  }
);

/* =========================================================
   JOB STATUS
========================================================= */

app.get(
  "/translate-status",
  (
    req,
    res
  ) => {
    const shop =
      req.query.shop;

    if (
      getSessionShop(req) !==
      shop
    ) {
      return res
        .status(403)
        .json({
          error:
            "Geen geldige sessie."
        });
    }

    res.json({
      running:
        job.running,

      mode:
        job.mode,

      shop:
        job.shop,

      total:
        job.total,

      pending:
        job.pending,

      processed:
        job.processed,

      skipped:
        job.skipped,

      failed:
        job.failed,

      current:
        job.current,

      startedAt:
        job.startedAt,

      finishedAt:
        job.finishedAt,

      errors:
        job.errors.slice(
          -30
        ),

      logs:
        job.logs.slice(
          -100
        )
    });
  }
);

/* =========================================================
   SERVER
========================================================= */

if (
  typeof fetch !==
  "function"
) {
  throw new Error(
    "Node.js 18 of nieuwer is vereist."
  );
}

app.listen(
  PORT,
  () => {
    console.log(
      `Maison Lévara Shopify API running on port ${PORT}`
    );
  }
);
