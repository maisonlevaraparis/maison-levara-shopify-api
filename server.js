const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const SHOPIFY_API_VERSION = "2026-07";

const SHOPIFY_CLIENT_ID =
  process.env.SHOPIFY_CLIENT_ID;

const SHOPIFY_CLIENT_SECRET =
  process.env.SHOPIFY_CLIENT_SECRET;

const REDIRECT_URI =
  process.env.REDIRECT_URI;

const OPENAI_API_KEY =
  process.env.OPENAI_API_KEY;

const OPENAI_MODEL =
  process.env.OPENAI_MODEL ||
  "gpt-5-mini";

const SHOPIFY_SCOPES =
  "write_products,write_files";

const TOKEN_FILE =
  process.env.TOKEN_FILE ||
  path.join(
    "/tmp",
    "maison-levara-shopify-tokens.json"
  );

const oauthStates =
  new Map();

const sessions =
  new Map();

const tokens =
  loadTokens();

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
  errors: [],
};

app.use(
  express.json({
    limit: "12mb",
  })
);

app.use(
  express.urlencoded({
    extended: true,
  })
);

/* =========================================================
   BASIC HELPERS
========================================================= */

function sleep(ms) {
  return new Promise(
    (resolve) =>
      setTimeout(resolve, ms)
  );
}

function validShop(shop) {
  return (
    typeof shop === "string" &&
    /^[a-z0-9][a-z0-9-]*\.myshopify\.com$/i.test(
      shop
    )
  );
}

function normalize(value) {
  return String(
    value || ""
  )
    .normalize("NFD")
    .replace(
      /[\u0300-\u036f]/g,
      ""
    )
    .toLowerCase()
    .replace(
      /[^a-z0-9]+/g,
      " "
    )
    .trim();
}

function log(message) {
  const line =
    `[${new Date().toISOString()}] ${message}`;

  job.logs.push(line);

  if (
    job.logs.length >
    500
  ) {
    job.logs.shift();
  }

  console.log(line);
}

/* =========================================================
   TOKEN STORAGE
========================================================= */

function loadTokens() {
  try {
    if (
      !fs.existsSync(
        TOKEN_FILE
      )
    ) {
      return new Map();
    }

    const parsed =
      JSON.parse(
        fs.readFileSync(
          TOKEN_FILE,
          "utf8"
        )
      );

    return new Map(
      Object.entries(parsed)
    );
  } catch {
    return new Map();
  }
}

function saveTokens() {
  try {
    fs.mkdirSync(
      path.dirname(
        TOKEN_FILE
      ),
      {
        recursive: true,
      }
    );

    fs.writeFileSync(
      TOKEN_FILE,
      JSON.stringify(
        Object.fromEntries(
          tokens
        ),
        null,
        2
      ),
      {
        mode: 0o600,
      }
    );
  } catch (error) {
    log(
      `Tokenopslag waarschuwing: ${error.message}`
    );
  }
}

/* =========================================================
   SESSIONS
========================================================= */

function parseCookies(req) {
  const result = {};

  for (
    const part of
      (
        req.headers.cookie ||
        ""
      ).split(";")
  ) {
    const index =
      part.indexOf("=");

    if (
      index < 0
    ) {
      continue;
    }

    result[
      part
        .slice(
          0,
          index
        )
        .trim()
    ] =
      decodeURIComponent(
        part
          .slice(
            index + 1
          )
          .trim()
      );
  }

  return result;
}

function createSession(shop) {
  const id =
    crypto.randomBytes(
      32
    ).toString("hex");

  sessions.set(
    id,
    {
      shop,

      expiresAt:
        Date.now() +
        24 *
          60 *
          60 *
          1000,
    }
  );

  return id;
}

function setSessionCookie(
  res,
  shop
) {
  const id =
    createSession(shop);

  res.setHeader(
    "Set-Cookie",
    `ml_session=${encodeURIComponent(
      id
    )}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`
  );
}

function getSessionShop(req) {
  const id =
    parseCookies(
      req
    ).ml_session;

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

/* =========================================================
   SHOPIFY HMAC
========================================================= */

function verifyHmac(query) {
  const {
    hmac,
    ...params
  } = query;

  if (
    !hmac ||
    !SHOPIFY_CLIENT_SECRET
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
        SHOPIFY_CLIENT_SECRET
      )
      .update(message)
      .digest("hex");

  try {
    return crypto.timingSafeEqual(
      Buffer.from(
        digest,
        "utf8"
      ),
      Buffer.from(
        String(hmac),
        "utf8"
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
  accessToken,
  query,
  variables = {}
) {
  let lastError =
    null;

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
            method:
              "POST",

            headers: {
              "Content-Type":
                "application/json",

              "X-Shopify-Access-Token":
                accessToken,
            },

            body:
              JSON.stringify({
                query,
                variables,
              }),
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
            "Shopify rate limit."
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

      if (
        !response.ok
      ) {
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
              (error) =>
                error.message
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
    } catch (
      error
    ) {
      lastError =
        error;

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
      "Shopify API request failed."
    )
  );
}

/* =========================================================
   PRODUCT QUERY
========================================================= */

const PRODUCTS_QUERY = `
  query GetProducts($after: String) {
    products(
      first: 100
      after: $after
    ) {
      nodes {
        id
        legacyResourceId

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

          linkedMetafield {
            namespace
            key
          }

          optionValues {
            id
            name
            hasVariants
            linkedMetafieldValue
          }
        }

        media(
          first: 250
        ) {
          nodes {
            id
            alt
            mediaContentType
          }
        }

        metafields(
          first: 100
        ) {
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
  accessToken
) {
  const products = [];

  let after = null;

  while (
    true
  ) {
    const data =
      await shopifyGraphQL(
        shop,
        accessToken,
        PRODUCTS_QUERY,
        {
          after,
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
   DONE MARKER
========================================================= */

function isDone(product) {
  return product.metafields.nodes.some(
    (field) =>
      field.namespace ===
        "maison_levara" &&
      field.key ===
        "fr_translation_v1" &&
      field.value ===
        "done"
  );
}

async function markDone(
  shop,
  token,
  productId
) {
  const mutation = `
    mutation MarkProductDone(
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
              "done",
          },
        ],
      }
    );

  const errors =
    data.metafieldsSet
      .userErrors || [];

  if (
    errors.length
  ) {
    throw new Error(
      errors
        .map(
          (error) =>
            error.message
        )
        .join(" | ")
    );
  }
}

/* =========================================================
   HTML PROTECTION
========================================================= */

function protectHtml(
  html
) {
  const tags = [];
  const attributes = [];
  const rawBlocks = [];

  let source =
    String(
      html || ""
    );

  source =
    source.replace(
      /<(script|style)\b[\s\S]*?<\/\1>/gi,
      (block) => {
        const token =
          `___ML_RAW_${String(
            rawBlocks.length
          ).padStart(
            5,
            "0"
          )}___`;

        rawBlocks.push({
          token,
          block,
        });

        return token;
      }
    );

  source =
    source.replace(
      /<[^>]*>/g,
      (tag) => {
        let protectedTag =
          tag;

        protectedTag =
          protectedTag.replace(
            /\b(alt|title|href|src)\s*=\s*(["'])([\s\S]*?)\2/gi,
            (
              full,
              name,
              quote,
              value
            ) => {
              const id =
                attributes.length;

              const token =
                `___ML_ATTR_${String(
                  id
                ).padStart(
                  5,
                  "0"
                )}___`;

              attributes.push({
                id,
                name:
                  name.toLowerCase(),

                value,

                translatable:
                  /^(alt|title)$/i.test(
                    name
                  ),
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
            protectedTag,
        });

        return token;
      }
    );

  return {
    html:
      source,

    tags,

    attributes,

    rawBlocks,
  };
}

function restoreHtml(
  translated,
  prepared,
  translatedAttributes
) {
  let html =
    String(
      translated || ""
    );

  const attrMap =
    new Map(
      (
        translatedAttributes ||
        []
      ).map(
        (item) => [
          Number(
            item.id
          ),
          String(
            item.value ||
              ""
          ),
        ]
      )
    );

  function escapeAttribute(
    value
  ) {
    return String(
      value
    )
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

    let restoredTag =
      item.tag;

    for (
      const attribute of
        prepared.attributes
    ) {
      const token =
        `___ML_ATTR_${String(
          attribute.id
        ).padStart(
          5,
          "0"
        )}___`;

      if (
        !restoredTag.includes(
          token
        )
      ) {
        continue;
      }

      let value =
        attribute.value;

      if (
        attribute.translatable &&
        attrMap.has(
          attribute.id
        )
      ) {
        value =
          attrMap.get(
            attribute.id
          );
      }

      restoredTag =
        restoredTag.replace(
          token,
          escapeAttribute(
            value
          )
        );
    }

    if (
      /___ML_ATTR_\d{5}___/.test(
        restoredTag
      )
    ) {
      throw new Error(
        "HTML-attribuut placeholder ontbreekt."
      );
    }

    html =
      html.replace(
        item.token,
        restoredTag
      );
  }

  for (
    const raw of
      prepared.rawBlocks
  ) {
    if (
      html.split(
        raw.token
      ).length -
        1 !==
      1
    ) {
      throw new Error(
        "Beschermd HTML-blok ontbreekt."
      );
    }

    html =
      html.replace(
        raw.token,
        raw.block
      );
  }

  if (
    /___ML_(TAG|ATTR|RAW)_\d{5}___/.test(
      html
    )
  ) {
    throw new Error(
      "Onopgeloste HTML placeholder gevonden."
    );
  }

  return html;
}

function htmlTagList(
  html
) {
  return [
    ...String(
      html || ""
    ).matchAll(
      /<\s*(\/?)\s*([a-zA-Z0-9]+)/g
    ),
  ].map(
    (match) =>
      `${match[1] ? "/" : ""}${match[2].toLowerCase()}`
  );
}

function htmlUrlList(
  html
) {
  return [
    ...String(
      html || ""
    ).matchAll(
      /\b(?:href|src)\s*=\s*["']([^"']+)["']/gi
    ),
  ]
    .map(
      (match) =>
        match[1]
    )
    .sort();
}

function assertHtmlSafe(
  before,
  after
) {
  const beforeTags =
    htmlTagList(
      before
    );

  const afterTags =
    htmlTagList(
      after
    );

  if (
    beforeTags.length !==
      afterTags.length ||
    beforeTags.some(
      (
        value,
        index
      ) =>
        value !==
        afterTags[index]
    )
  ) {
    throw new Error(
      "HTML-tagstructuur is gewijzigd."
    );
  }

  const beforeUrls =
    htmlUrlList(
      before
    );

  const afterUrls =
    htmlUrlList(
      after
    );

  if (
    beforeUrls.length !==
      afterUrls.length ||
    beforeUrls.some(
      (
        value,
        index
      ) =>
        value !==
        afterUrls[index]
    )
  ) {
    throw new Error(
      "Een product-URL in de HTML is gewijzigd."
    );
  }
}

/* =========================================================
   FRENCH NAMES
========================================================= */

const FRENCH_NAMES = [
  "Adèle",
  "Agathe",
  "Agnès",
  "Alix",
  "Amélie",
  "Anaïs",
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
  "Daphné",
  "Delphine",
  "Diane",
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
  "Zoé",
];

const FRENCH_NAME_KEYS =
  new Set(
    FRENCH_NAMES.map(
      normalize
    )
  );

/* =========================================================
   OPENAI
========================================================= */

const PRODUCT_SCHEMA = {
  type:
    "object",

  additionalProperties:
    false,

  properties: {
    firstName: {
      type:
        "string",
    },

    descriptor: {
      type:
        "string",
    },

    productType: {
      type:
        "string",
    },

    descriptionHtml: {
      type:
        "string",
    },

    seoTitle: {
      type:
        "string",
    },

    seoDescription: {
      type:
        "string",
    },

    htmlAttributes: {
      type:
        "array",

      items: {
        type:
          "object",

        additionalProperties:
          false,

        properties: {
          id: {
            type:
              "integer",
          },

          value: {
            type:
              "string",
          },
        },

        required: [
          "id",
          "value",
        ],
      },
    },

    options: {
      type:
        "array",

      items: {
        type:
          "object",

        additionalProperties:
          false,

        properties: {
          index: {
            type:
              "integer",
          },

          name: {
            type:
              "string",
          },

          values: {
            type:
              "array",

            items: {
              type:
                "object",

              additionalProperties:
                false,

              properties: {
                id: {
                  type:
                    "string",
                },

                name: {
                  type:
                    "string",
                },
              },

              required: [
                "id",
                "name",
              ],
            },
          },
        },

        required: [
          "index",
          "name",
          "values",
        ],
      },
    },

    media: {
      type:
        "array",

      items: {
        type:
          "object",

        additionalProperties:
          false,

        properties: {
          id: {
            type:
              "string",
          },

          alt: {
            type:
              "string",
          },
        },

        required: [
          "id",
          "alt",
        ],
      },
    },
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
    "media",
  ],
};

const BF_SCHEMA = {
  type:
    "object",

  additionalProperties:
    false,

  properties: {
    translations: {
      type:
        "array",

      items: {
        type:
          "object",

        additionalProperties:
          false,

        properties: {
          id: {
            type:
              "integer",
          },

          text: {
            type:
              "string",
          },
        },

        required: [
          "id",
          "text",
        ],
      },
    },
  },

  required: [
    "translations",
  ],
};

const PRODUCT_PROMPT = `
Je bent de vaste Franse e-commerce copywriter van Maison Lévara Paris.

Vertaal de volledige aangeleverde productdata naar natuurlijk,
professioneel Frans voor een moderne Franse modewebshop.

PRODUCTNAAM:
Gebruik exact:
"Franse voornaam | Franse productomschrijving"

De eerste helft moet een echte Franse voornaam zijn.
De tweede helft moet een korte, duidelijke Franse omschrijving
van het product zijn.

Gebruik nooit een Nederlandse, Italiaanse, Spaanse of Engelse
voornaam.

De volledige titel moet uniek zijn ten opzichte van existingTitles.

De stijl moet aansluiten op de oude Luno Milano-naamstructuur:
Voornaam | productomschrijving.

BESCHRIJVING:
Vertaal alle klantzichtbare tekst.
Vertaal ook maattabellen, tabellen en teksten in tabellen.

HTML:
Behoud alle HTML-placeholders exact.
Voeg geen HTML-tags toe.
Verwijder geen HTML-tags.
Verander nooit href, src of URL's.
Verander nooit class, id of data-* attributen.

Vertaal normale alt/title-attributen via htmlAttributes.

Behoud:
- cijfers
- percentages
- maten
- afmetingen
- eenheden
- SKU's
- barcodes
- productcodes
- technische codes

One Size -> Taille unique.

OPTIES:
Size / Taglia -> Taille
Color / Colore / Kleur / Colour -> Couleur
Material -> Matière

Vertaal normale kleurwaarden naar Frans.

Laat XS, S, M, L, XL, XXL en numerieke maatcodes intact.

PRODUCTTYPE:
Vertaal naar Frans wanneer aanwezig.

SEO:
Vertaal SEO title en SEO description naar natuurlijk Frans.
Gebruik geen keyword stuffing.

MEDIA:
Vertaal alleen de alt-teksten.

WIJZIG NOOIT:
- prijzen
- voorraad
- SKU
- barcode
- handle
- product-ID
- variant-ID
- afbeeldingen

Gebruik geen nieuwe producteigenschappen die niet in de bron staan.

Geef alleen het gevraagde JSON-object terug.
`;

const BF_PROMPT = `
Vertaal de tekst van een BF Size Chart naar natuurlijk Frans.

Vertaal:
- buttonText
- titels
- beschrijvingen
- kolomteksten
- meetnamen
- kleurwoorden
- woorden in tabelcellen

Taglia -> Taille
Size -> Taille
Colore -> Couleur
Color -> Couleur
Kleur -> Couleur
One Size -> Taille unique

Behoud exact:
- cijfers
- maataanduidingen
- afmetingen
- eenheden
- percentages
- technische codes
- HTML-tags en placeholders

Verander nooit getallen of maten.

Geef alleen het gevraagde JSON-object terug.
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
  systemPrompt,
  schema,
  payload
) {
  if (
    !OPENAI_API_KEY
  ) {
    throw new Error(
      "OPENAI_API_KEY ontbreekt."
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

      const timeout =
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
              method:
                "POST",

              signal:
                controller.signal,

              headers: {
                "Content-Type":
                  "application/json",

                Authorization:
                  `Bearer ${OPENAI_API_KEY}`,
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
                            systemPrompt,
                        },
                      ],
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
                            ),
                        },
                      ],
                    },
                  ],

                  max_output_tokens:
                    12000,

                  text: {
                    format: {
                      type:
                        "json_schema",

                      name:
                        "maison_levara_translation",

                      strict:
                        true,

                      schema,
                    },
                  },
                }),
            }
          );
      } finally {
        clearTimeout(
          timeout
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
            "OpenAI rate limit."
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

      if (
        !text
      ) {
        throw new Error(
          "OpenAI gaf geen output terug."
        );
      }

      return JSON.parse(
        text
      );
    } catch (
      error
    ) {
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

/* =========================================================
   PRODUCT TRANSLATION
========================================================= */

function buildProductPayload(
  product,
  reservedTitles
) {
  const prepared =
    protectHtml(
      product.descriptionHtml ||
        ""
    );

  return {
    currentTitle:
      product.title,

    currentProductType:
      product.productType ||
      "",

    descriptionHtml:
      prepared.html,

    htmlAttributes:
      prepared.attributes,

    seo: {
      title:
        product.seo?.title ||
        "",

      description:
        product.seo?.description ||
        "",
    },

    options:
      product.options.map(
        (
          option,
          index
        ) => ({
          index,

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
                  value.name,
              })
            ),
        })
      ),

    media:
      product.media.nodes.map(
        (media) => ({
          id:
            media.id,

          alt:
            media.alt ||
            "",
        })
      ),

    existingTitles:
      [
        ...reservedTitles,
      ],
  };
}

function uniqueFallbackTitle(
  descriptor,
  reservedTitles,
  start
) {
  for (
    let offset = 0;
    offset <
      FRENCH_NAMES.length;
    offset++
  ) {
    const name =
      FRENCH_NAMES[
        (
          start +
          offset
        ) %
          FRENCH_NAMES.length
      ];

    const title =
      `${name} | ${descriptor}`;

    if (
      !reservedTitles.has(
        normalize(title)
      )
    ) {
      return title;
    }
  }

  throw new Error(
    "Geen unieke Franse productnaam gevonden."
  );
}

function optionValuesUnique(
  product,
  result
) {
  for (
    const option of
      product.options
  ) {
    const translated =
      result.options.find(
        (item) =>
          Number(
            item.index
          ) ===
          Number(
            option.position -
              1
          )
      );

    if (
      !translated
    ) {
      continue;
    }

    const seen =
      new Set();

    for (
      const original of
        option.optionValues
    ) {
      const match =
        (
          translated.values ||
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

      const finalValue =
        String(
          match?.name ??
            original.name
        ).trim();

      const key =
        normalize(
          finalValue
        );

      if (
        !key
      ) {
        continue;
      }

      if (
        seen.has(key)
      ) {
        return false;
      }

      seen.add(key);
    }
  }

  return true;
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

  const payload =
    buildProductPayload(
      product,
      reservedTitles
    );

  for (
    let attempt = 0;
    attempt < 6;
    attempt++
  ) {
    payload.retryInstruction =
      attempt
        ? `La précédente proposition de titre "${payload.previousTitle}" ou les valeurs d'options n'étaient pas valides. Choisis une autre combinaison et garde toutes les valeurs d'une même option uniques.`
        : "";

    const result =
      await openAIJson(
        PRODUCT_PROMPT,
        PRODUCT_SCHEMA,
        payload
      );

    let firstName =
      String(
        result.firstName ||
          ""
      ).trim();

    if (
      !FRENCH_NAME_KEYS.has(
        normalize(
          firstName
        )
      )
    ) {
      firstName =
        FRENCH_NAMES[
          (
            index +
            attempt
          ) %
            FRENCH_NAMES.length
        ];
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

    if (
      !descriptor
    ) {
      continue;
    }

    let title =
      `${firstName} | ${descriptor}`.trim();

    payload.previousTitle =
      title;

    if (
      reservedTitles.has(
        normalize(
          title
        )
      )
    ) {
      continue;
    }

    if (
      !optionValuesUnique(
        product,
        result
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

    if (
      reservedTitles.has(
        normalize(
          title
        )
      )
    ) {
      title =
        uniqueFallbackTitle(
          descriptor,
          reservedTitles,
          index
        );
    }

    reservedTitles.add(
      normalize(
        title
      )
    );

    return {
      title,

      productType:
        product.productType
          ? String(
              result.productType ||
                product.productType
            ).trim()
          : "",

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
          : [],
    };
  }

  throw new Error(
    `Geen geldige unieke Franse vertaling voor "${product.title}".`
  );
}

/* =========================================================
   PRODUCT WRITE
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

  const input = {
    id:
      product.id,

    title:
      translated.title,

    descriptionHtml:
      translated.descriptionHtml,

    seo: {
      title:
        translated.seoTitle,

      description:
        translated.seoDescription,
    },
  };

  if (
    product.productType
  ) {
    input.productType =
      translated.productType ||
      product.productType;
  }

  const data =
    await shopifyGraphQL(
      shop,
      token,
      mutation,
      {
        product:
          input,
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
          (error) =>
            error.message
        )
        .join(" | ")
    );
  }
}

/* =========================================================
   OPTION WRITE
========================================================= */

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
    if (
      option.linkedMetafield
    ) {
      /*
        A linked option is controlled through
        its linked metafield. Do not mutate the
        source value and risk breaking that link.
      */
      continue;
    }

    const translatedOption =
      translated.options.find(
        (item) =>
          Number(
            item.index
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

    const updates =
      option.optionValues
        .map(
          (
            original
          ) => {
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

            if (
              !match
            ) {
              return null;
            }

            const value =
              String(
                match.name ||
                  ""
              ).trim();

            if (
              !value ||
              value ===
                original.name.trim()
            ) {
              return null;
            }

            return {
              id:
                original.id,

              name:
                value,
            };
          }
        )
        .filter(
          Boolean
        );

    const optionName =
      String(
        translatedOption.name ||
          ""
      ).trim();

    const nameChanged =
      optionName &&
      optionName !==
        option.name.trim();

    if (
      !nameChanged &&
      !updates.length
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
              optionName ||
              option.name,

            position:
              option.position,
          },

          optionValuesToUpdate:
            updates,
        }
      );

    const errors =
      data.productOptionUpdate
        .userErrors || [];

    if (
      errors.length
    ) {
      throw new Error(
        errors
          .map(
            (error) =>
              error.message
          )
          .join(" | ")
      );
    }
  }
}

/* =========================================================
   MEDIA ALT TEXT
========================================================= */

async function updateMediaAlt(
  shop,
  token,
  product,
  translated
) {
  const files =
    translated.media
      .map(
        (item) => {
          const original =
            product.media.nodes.find(
              (media) =>
                media.id ===
                item.id
            );

          if (
            !original ||
            typeof item.alt !==
              "string"
          ) {
            return null;
          }

          if (
            String(
              original.alt ||
                ""
            ) ===
            String(
              item.alt
            )
          ) {
            return null;
          }

          return {
            id:
              item.id,

            alt:
              item.alt,
          };
        }
      )
      .filter(
        Boolean
      );

  if (
    !files.length
  ) {
    return;
  }

  const mutation = `
    mutation UpdateFiles(
      $files: [FileUpdateInput!]!
    ) {
      fileUpdate(
        files: $files
      ) {
        files {
          id
          alt
        }

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
        files,
      }
    );

  const errors =
    data.fileUpdate
      .userErrors || [];

  if (
    errors.length
  ) {
    throw new Error(
      errors
        .map(
          (error) =>
            error.message
        )
        .join(" | ")
    );
  }
}

/* =========================================================
   ONE PRODUCT
========================================================= */

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

  await updateMediaAlt(
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
   BF SIZE CHARTS
========================================================= */

const BF_QUERY = `
  query BFSizeCharts {
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

async function getBFSizeCharts(
  shop,
  token
) {
  const data =
    await shopifyGraphQL(
      shop,
      token,
      BF_QUERY
    );

  return {
    shopId:
      data.shop.id,

    metafield:
      data.shop.metafield,
  };
}

function isNumericLike(
  value
) {
  const text =
    String(
      value || ""
    ).trim();

  if (
    !text
  ) {
    return true;
  }

  return (
    /^[-+]?\d+(?:[.,]\d+)?$/.test(
      text
    ) ||
    /^[-+]?\d+(?:[.,]\d+)?\s*(?:cm|mm|m|kg|g|lb|lbs|in|inch|inches|%|°c|°f)$/i.test(
      text
    ) ||
    /^\d+\s*[-–]\s*\d+$/.test(
      text
    ) ||
    /^\d+(?:[.,]\d+)?\s*[x×]\s*\d+(?:[.,]\d+)?$/i.test(
      text
    )
  );
}

function collectBFStrings(
  node,
  result = [],
  currentPath = []
) {
  if (
    Array.isArray(node)
  ) {
    node.forEach(
      (
        item,
        index
      ) =>
        collectBFStrings(
          item,
          result,
          currentPath.concat(
            String(index)
          )
        )
    );

    return result;
  }

  if (
    !node ||
    typeof node !==
      "object"
  ) {
    return result;
  }

  for (
    const [
      key,
      value
    ] of Object.entries(
      node
    )
  ) {
    const nextPath =
      currentPath.concat(
        key
      );

    const productConditionTitle =
      key ===
        "title" &&
      node.type ===
        "product" &&
      node.id != null;

    if (
      typeof value ===
        "string" &&
      [
        "buttonText",
        "title",
        "descriptionTop",
        "descriptionBottom",
      ].includes(
        key
      )
    ) {
      if (
        !productConditionTitle &&
        value.trim() &&
        !isNumericLike(
          value
        )
      ) {
        result.push({
          path:
            nextPath,

          text:
            value,
        });
      }

      continue;
    }

    if (
      key.toLowerCase() ===
        "values"
    ) {
      collectBFValues(
        value,
        result,
        nextPath
      );

      continue;
    }

    collectBFStrings(
      value,
      result,
      nextPath
    );
  }

  return result;
}

function collectBFValues(
  node,
  result,
  currentPath
) {
  if (
    Array.isArray(node)
  ) {
    node.forEach(
      (
        item,
        index
      ) =>
        collectBFValues(
          item,
          result,
          currentPath.concat(
            String(index)
          )
        )
    );

    return;
  }

  if (
    typeof node ===
      "string"
  ) {
    if (
      node.trim() &&
      !isNumericLike(
        node
      )
    ) {
      result.push({
        path:
          currentPath,

        text:
          node,
      });
    }

    return;
  }

  if (
    node &&
    typeof node ===
      "object"
  ) {
    for (
      const [
        key,
        value
      ] of Object.entries(
        node
      )
    ) {
      collectBFValues(
        value,
        result,
        currentPath.concat(
          key
        )
      );
    }
  }
}

function setDeepValue(
  root,
  pathParts,
  value
) {
  let current =
    root;

  for (
    let i = 0;
    i <
      pathParts.length -
        1;
    i++
  ) {
    current =
      current[
        pathParts[i]
      ];
  }

  current[
    pathParts[
      pathParts.length -
        1
    ]
  ] =
    value;
}

async function translateBFStrings(
  entries
) {
  const results =
    new Array(
      entries.length
    );

  const chunkSize =
    60;

  for (
    let start = 0;
    start <
      entries.length;
    start +=
      chunkSize
  ) {
    const chunk =
      entries.slice(
        start,
        start +
          chunkSize
      );

    const payload = {
      items:
        chunk.map(
          (
            item,
            index
          ) => {
            const prepared =
              protectHtml(
                item.text
              );

            return {
              id:
                index,

              text:
                prepared.html,

              attributes:
                prepared.attributes,
            };
          }
        ),
    };

    const response =
      await openAIJson(
        BF_PROMPT,
        {
          type:
            "object",

          additionalProperties:
            false,

          properties: {
            translations: {
              type:
                "array",

              items: {
                type:
                  "object",

                additionalProperties:
                  false,

                properties: {
                  id: {
                    type:
                      "integer",
                  },

                  text: {
                    type:
                      "string",
                  },
                },

                required: [
                  "id",
                  "text",
                ],
              },
            },
          },

          required: [
            "translations",
          ],
        },
        payload
      );

    for (
      const item of
        response.translations ||
        []
    ) {
      const index =
        Number(
          item.id
        );

      if (
        !Number.isInteger(
          index
        ) ||
        index < 0 ||
        index >=
          chunk.length
      ) {
        continue;
      }

      /*
        BF strings may themselves contain HTML.
        Preserve that HTML exactly.
      */
      const prepared =
        protectHtml(
          chunk[index].text
        );

      let restored =
        String(
          item.text ||
            ""
        );

      try {
        /*
          When the BF string contains
          HTML, OpenAI sees placeholders.
          Reuse restoreHtml for safety.
        */
        const attrs =
          Array.isArray(
            item.attributes
          )
            ? item.attributes
            : [];

        restored =
          restoreHtml(
            restored,
            prepared,
            attrs
          );
      } catch {
        /*
          For plain text without HTML,
          restoreHtml still works only
          when there are zero tags.
        */
        if (
          prepared.tags.length ===
          0
        ) {
          restored =
            String(
              item.text ||
                ""
            );
        } else {
          throw new Error(
            `BF HTML-vertaling ongeldig voor "${chunk[index].text}".`
          );
        }
      }

      assertHtmlSafe(
        chunk[index].text,
        restored
      );

      results[
        start +
          index
      ] =
        restored;
    }
  }

  return results;
}

function syncBFProductTitles(
  root,
  renamedByLegacyId,
  renamedByGid
) {
  if (
    Array.isArray(root)
  ) {
    root.forEach(
      (item) =>
        syncBFProductTitles(
          item,
          renamedByLegacyId,
          renamedByGid
        )
    );

    return;
  }

  if (
    !root ||
    typeof root !==
      "object"
  ) {
    return;
  }

  if (
    root.type ===
      "product" &&
    typeof root.title ===
      "string"
  ) {
    const id =
      root.id != null
        ? String(
            root.id
          )
        : "";

    if (
      renamedByLegacyId.has(
        id
      )
    ) {
      root.title =
        renamedByLegacyId.get(
          id
        );
    } else if (
      renamedByGid.has(
        id
      )
    ) {
      root.title =
        renamedByGid.get(
          id
        );
    }
  }

  Object.values(
    root
  ).forEach(
    (value) =>
      syncBFProductTitles(
        value,
        renamedByLegacyId,
        renamedByGid
      )
  );
}

async function updateBFSizeCharts(
  shop,
  token,
  products,
  renamedProducts
) {
  const bf =
    await getBFSizeCharts(
      shop,
      token
    );

  if (
    !bf.metafield
  ) {
    log(
      "BF size_charts niet gevonden; geen BF-write uitgevoerd."
    );

    return;
  }

  let original;

  try {
    original =
      JSON.parse(
        bf.metafield.value
      );
  } catch {
    throw new Error(
      "BF size_charts bevat ongeldige JSON."
    );
  }

  const updated =
    JSON.parse(
      JSON.stringify(
        original
      )
    );

  const entries =
    collectBFStrings(
      updated
    ).map(
      (entry) => ({
        ...entry,

        prepared:
          protectHtml(
            entry.text
          ),
      })
    );

  if (
    entries.length
  ) {
    log(
      `BF: ${entries.length} tekstvelden gevonden.`
    );

    const translated =
      await translateBFStrings(
        entries
      );

    for (
      let i = 0;
      i <
        entries.length;
      i++
    ) {
      if (
        typeof translated[i] !==
          "string"
      ) {
        throw new Error(
          `BF vertaling ontbreekt voor "${entries[i].text}".`
        );
      }

      setDeepValue(
        updated,
        entries[i].path,
        translated[i]
      );
    }
  }

  const renamedByLegacyId =
    new Map();

  const renamedByGid =
    new Map();

  for (
    const product of
      products
  ) {
    renamedByLegacyId.set(
      String(
        product.legacyResourceId
      ),
      product.title
    );

    renamedByGid.set(
      String(
        product.id
      ),
      product.title
    );
  }

  for (
    const [
      id,
      title
    ] of
      renamedProducts
  ) {
    if (
      id.startsWith(
        "gid://"
      )
    ) {
      renamedByGid.set(
        id,
        title
      );
    } else {
      renamedByLegacyId.set(
        id,
        title
      );
    }
  }

  syncBFProductTitles(
    updated,
    renamedByLegacyId,
    renamedByGid
  );

  const mutation = `
    mutation UpdateBF(
      $metafields: [MetafieldsSetInput!]!
    ) {
      metafieldsSet(
        metafields: $metafields
      ) {
        metafields {
          id
          namespace
          key
          type
          value
          compareDigest
        }

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
              bf.shopId,

            namespace:
              "sizechartsrelentless",

            key:
              "size_charts",

            type:
              "json",

            value:
              JSON.stringify(
                updated
              ),

            compareDigest:
              bf.metafield
                .compareDigest ||
              null,
          },
        ],
      }
    );

  const errors =
    data.metafieldsSet
      .userErrors || [];

  if (
    errors.length
  ) {
    throw new Error(
      errors
        .map(
          (error) =>
            error.message
        )
        .join(" | ")
    );
  }

  log(
    "BF Size Charts bijgewerkt."
  );
}

/* =========================================================
   FULL JOB
========================================================= */

async function runFullJob(
  shop
) {
  const connection =
    tokens.get(
      shop
    );

  if (
    !connection
  ) {
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
      "Shopify-productcatalogus ophalen..."
    );

    const products =
      await getAllProducts(
        shop,
        connection.accessToken
      );

    job.total =
      products.length;

    const pending =
      products.filter(
        (product) =>
          !isDone(
            product
          )
      );

    job.pending =
      pending.length;

    job.skipped =
      products.length -
      pending.length;

    const reservedTitles =
      new Set(
        products.map(
          (product) =>
            normalize(
              product.title
            )
        )
      );

    /*
      old/new title map for BF.
    */
    const renamedProducts =
      new Map();

    /*
      IMPORTANT:
      Existing completed products already have
      their final title. Store those too so BF
      stays synchronized.
    */
    for (
      const product of
        products
    ) {
      if (
        isDone(
          product
        )
      ) {
        renamedProducts.set(
          String(
            product.legacyResourceId
          ),
          product.title
        );

        renamedProducts.set(
          String(
            product.id
          ),
          product.title
        );
      }
    }

    log(
      `${products.length} producten gevonden.`
    );

    log(
      `${pending.length} producten worden verwerkt.`
    );

    let cursor =
      0;

    const workerCount =
      Math.min(
        3,
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
            product.title,
        };

        try {
          const translated =
            await processProduct(
              shop,
              connection.accessToken,
              product,
              reservedTitles,
              index
            );

          renamedProducts.set(
            String(
              product.legacyResourceId
            ),
            translated.title
          );

          renamedProducts.set(
            String(
              product.id
            ),
            translated.title
          );

          job.processed++;

          log(
            `KLAAR ${index + 1}/${pending.length}: ${product.title} -> ${translated.title}`
          );
        } catch (
          error
        ) {
          job.failed++;

          const message =
            `${product.title}: ${error.message}`;

          job.errors.push(
            message
          );

          if (
            job.errors.length >
            100
          ) {
            job.errors.shift();
          }

          log(
            `FOUT ${index + 1}/${pending.length}: ${message}`
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
            workerCount,
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

    /*
      Read again after product writes.
    */
    const updatedProducts =
      await getAllProducts(
        shop,
        connection.accessToken
      );

    log(
      "BF Size Chart verwerken..."
    );

    await updateBFSizeCharts(
      shop,
      connection.accessToken,
      updatedProducts,
      renamedProducts
    );

    log(
      `JOB KLAAR — verwerkt: ${job.processed}, overgeslagen: ${job.skipped}, fouten: ${job.failed}.`
    );
  } catch (
    error
  ) {
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
   ONE-PRODUCT TEST
========================================================= */

async function runTestOne(
  shop
) {
  const connection =
    tokens.get(
      shop
    );

  if (
    !connection
  ) {
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
      (item) =>
        !isDone(
          item
        )
    );

  if (
    !product
  ) {
    throw new Error(
      "Geen onvertaald product gevonden."
    );
  }

  const reservedTitles =
    new Set(
      products.map(
        (item) =>
          normalize(
            item.title
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

/* =========================================================
   HOME
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

/* =========================================================
   HEALTH
========================================================= */

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
          SHOPIFY_CLIENT_ID &&
          SHOPIFY_CLIENT_SECRET &&
          REDIRECT_URI
        ),

      openAIConfigured:
        Boolean(
          OPENAI_API_KEY
        ),

      model:
        OPENAI_MODEL,

      shopifyApiVersion:
        SHOPIFY_API_VERSION,

      scopes:
        SHOPIFY_SCOPES,
    });
  }
);

/* =========================================================
   AUTH START
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
      !validShop(
        shop
      )
    ) {
      return res
        .status(400)
        .send(
          "Ongeldige Shopify shop."
        );
    }

    if (
      !SHOPIFY_CLIENT_ID ||
      !SHOPIFY_CLIENT_SECRET ||
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
          10 *
            60 *
            1000,
      }
    );

    const authUrl =
      `https://${shop}/admin/oauth/authorize?` +
      new URLSearchParams({
        client_id:
          SHOPIFY_CLIENT_ID,

        scope:
          SHOPIFY_SCOPES,

        redirect_uri:
          REDIRECT_URI,

        state,
      }).toString();

    res.redirect(
      authUrl
    );
  }
);

/* =========================================================
   AUTH CALLBACK
========================================================= */

app.get(
  "/auth/callback",
  async (
    req,
    res
  ) => {
    const {
      code,
      shop,
      state,
    } = req.query;

    if (
      !validShop(
        shop
      )
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
                "application/x-www-form-urlencoded",
            },

            body:
              new URLSearchParams({
                client_id:
                  SHOPIFY_CLIENT_ID,

                client_secret:
                  SHOPIFY_CLIENT_SECRET,

                code,
              }),
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
            data.scope,
        }
      );

      saveTokens();

      setSessionCookie(
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
    } catch (
      error
    ) {
      res
        .status(500)
        .send(
          `Shopify verbinding mislukt: ${error.message}`
        );
    }
  }
);

/* =========================================================
   PRODUCTS READ CHECK
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
      !validShop(
        shop
      )
    ) {
      return res
        .status(400)
        .send(
          "Ongeldige Shopify shop."
        );
    }

    const connection =
      tokens.get(
        shop
      );

    if (
      !connection
    ) {
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
              (product) => ({
                id:
                  product.id,

                title:
                  product.title,

                handle:
                  product.handle,

                productType:
                  product.productType,

                options:
                  product.options.map(
                    (option) => ({
                      name:
                        option.name,

                      values:
                        option.optionValues.map(
                          (value) =>
                            value.name
                        ),
                    })
                  ),

                mediaCount:
                  product.media.nodes.length,

                metafieldCount:
                  product.metafields.nodes.length,

                translated:
                  isDone(
                    product
                  ),
              })
            ),
      });
    } catch (
      error
    ) {
      res
        .status(500)
        .json({
          error:
            error.message,
        });
    }
  }
);

/* =========================================================
   BF DIAGNOSE
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
      !validShop(
        shop
      )
    ) {
      return res
        .status(400)
        .json({
          error:
            "Ongeldige Shopify shop.",
        });
    }

    const connection =
      tokens.get(
        shop
      );

    if (
      !connection
    ) {
      return res
        .status(401)
        .json({
          error:
            "Shopify is niet verbonden.",
        });
    }

    try {
      const bf =
        await getBFSizeCharts(
          shop,
          connection.accessToken
        );

      if (
        !bf.metafield
      ) {
        return res
          .status(404)
          .json({
            found:
              false,

            message:
              "sizechartsrelentless.size_charts niet gevonden.",
          });
      }

      let parsed =
        null;

      try {
        parsed =
          JSON.parse(
            bf.metafield.value
          );
      } catch {
        parsed =
          null;
      }

      res.json({
        found:
          true,

        id:
          bf.metafield.id,

        namespace:
          bf.metafield.namespace,

        key:
          bf.metafield.key,

        type:
          bf.metafield.type,

        compareDigest:
          bf.metafield
            .compareDigest,

        json:
          parsed,

        value:
          parsed === null
            ? bf.metafield.value
            : undefined,
      });
    } catch (
      error
    ) {
      res
        .status(500)
        .json({
          error:
            error.message,
        });
    }
  }
);

/* =========================================================
   ADMIN
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
      !validShop(
        shop
      )
    ) {
      return res
        .status(400)
        .send(
          "Ongeldige Shopify shop."
        );
    }

    if (
      getSessionShop(
        req
      ) !==
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
  font-family:Arial,sans-serif;
  max-width:1000px;
  margin:40px auto;
  padding:0 20px;
}

.card{
  background:#f4f4f4;
  padding:20px;
  border-radius:10px;
  margin:18px 0;
}

button{
  background:#111;
  color:#fff;
  border:0;
  border-radius:7px;
  padding:14px 20px;
  margin:5px 8px 5px 0;
  cursor:pointer;
  font-size:15px;
}

button:disabled{
  opacity:.45;
  cursor:not-allowed;
}

pre{
  background:#111;
  color:#eee;
  padding:16px;
  border-radius:8px;
  white-space:pre-wrap;
  max-height:520px;
  overflow:auto;
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
De automatisering vertaalt producttitel,
producttype, volledige beschrijving, SEO,
opties, maten, kleuren en media-altteksten.
</p>

<p>
De BF Size Charts worden na de productvertaling
naar Frans bijgewerkt en productkoppelingen worden
gesynchroniseerd met de nieuwe productnamen.
</p>

<p>
<strong>
Prijzen, voorraad, SKU's, barcodes, handles,
afbeeldingen en product-ID's worden niet gewijzigd.
</strong>
</p>

<p>
Productnamen:
<strong>
Franse voornaam | Franse productomschrijving
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

<pre id="logs">
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
        "Dit start alle nog niet verwerkte producten en werkt daarna de BF Size Charts bij. Doorgaan?"
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
   START ONE
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
      !validShop(
        shop
      )
    ) {
      return res
        .status(400)
        .json({
          error:
            "Ongeldige Shopify shop.",
        });
    }

    if (
      getSessionShop(
        req
      ) !==
      shop
    ) {
      return res
        .status(403)
        .json({
          error:
            "Geen geldige sessie.",
        });
    }

    if (
      job.running
    ) {
      return res
        .status(409)
        .json({
          error:
            "Er draait al een job.",
        });
    }

    try {
      const result =
        await runTestOne(
          shop
        );

      res.json({
        ok:
          true,

        newTitle:
          result.title,
      });
    } catch (
      error
    ) {
      res
        .status(500)
        .json({
          error:
            error.message,
        });
    }
  }
);

/* =========================================================
   START ALL
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
      !validShop(
        shop
      )
    ) {
      return res
        .status(400)
        .json({
          error:
            "Ongeldige Shopify shop.",
        });
    }

    if (
      getSessionShop(
        req
      ) !==
      shop
    ) {
      return res
        .status(403)
        .json({
          error:
            "Geen geldige sessie.",
        });
    }

    if (
      job.running
    ) {
      return res
        .status(409)
        .json({
          error:
            "Er draait al een job.",
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
            "Shopify-token ontbreekt.",
        });
    }

    if (
      !OPENAI_API_KEY
    ) {
      return res
        .status(500)
        .json({
          error:
            "OPENAI_API_KEY ontbreekt.",
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
          true,
      });
  }
);

/* =========================================================
   STATUS
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
      getSessionShop(
        req
      ) !==
      shop
    ) {
      return res
        .status(403)
        .json({
          error:
            "Geen geldige sessie.",
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

      logs:
        job.logs.slice(
          -150
        ),

      errors:
        job.errors.slice(
          -30
        ),
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
