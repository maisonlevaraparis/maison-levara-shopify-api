const express = require("express");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const CLIENT_ID = process.env.SHOPIFY_CLIENT_ID;
const CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;

// Shopify stable Admin GraphQL API release.
const SHOPIFY_API_VERSION = "2026-07";

// OpenAI model can be changed in Render with OPENAI_MODEL.
// Default chosen for cost-sensitive, high-volume translation work.
const OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-5.6-luna";

const SHOPIFY_SCOPES = "write_products";

const oauthStates = new Map();
const shopTokens = new Map();
const sessions = new Map();

const job = {
  running: false,
  shop: null,
  total: 0,
  pending: 0,
  processed: 0,
  skipped: 0,
  failed: 0,
  current: null,
  startedAt: null,
  finishedAt: null,
  errors: [],
  logs: [],
};

app.use(express.json({ limit: "5mb" }));
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

function addLog(message) {
  const line = `[${new Date().toISOString()}] ${message}`;

  job.logs.push(line);

  if (job.logs.length > 250) {
    job.logs.shift();
  }

  console.log(line);
}

function parseCookies(req) {
  const result = {};

  for (const part of (req.headers.cookie || "").split(";")) {
    const index = part.indexOf("=");

    if (index < 0) {
      continue;
    }

    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    result[key] = decodeURIComponent(value);
  }

  return result;
}

function createSession(shop) {
  const sessionId = crypto.randomBytes(32).toString("hex");

  sessions.set(sessionId, {
    shop,
    expiresAt: Date.now() + 24 * 60 * 60 * 1000,
  });

  return sessionId;
}

function sessionShop(req) {
  const sessionId = parseCookies(req).ml_session;

  if (!sessionId) {
    return null;
  }

  const session = sessions.get(sessionId);

  if (!session) {
    return null;
  }

  if (session.expiresAt < Date.now()) {
    sessions.delete(sessionId);
    return null;
  }

  return session.shop;
}

function verifyHmac(query) {
  const { hmac, ...params } = query;

  if (!hmac || !CLIENT_SECRET) {
    return false;
  }

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
      Buffer.from(String(hmac), "utf8")
    );
  } catch {
    return false;
  }
}

async function shopifyGraphQL(
  shop,
  accessToken,
  query,
  variables = {}
) {
  let lastError = null;

  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      const response = await fetch(
        `https://${shop}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`,
        {
          method: "POST",

          headers: {
            "Content-Type": "application/json",
            "X-Shopify-Access-Token": accessToken,
          },

          body: JSON.stringify({
            query,
            variables,
          }),
        }
      );

      const body = await response.json();

      if (response.status === 429) {
        lastError = new Error("Shopify rate limit.");

        await sleep(
          1000 * 2 ** attempt
        );

        continue;
      }

      if (!response.ok) {
        throw new Error(
          `Shopify HTTP ${response.status}: ${JSON.stringify(body)}`
        );
      }

      if (body.errors?.length) {
        const message = body.errors
          .map((error) => error.message)
          .join(" | ");

        if (/throttl/i.test(message)) {
          lastError = new Error(message);

          await sleep(
            1000 * 2 ** attempt
          );

          continue;
        }

        throw new Error(message);
      }

      return body.data;
    } catch (error) {
      lastError = error;

      if (attempt === 4) {
        break;
      }

      await sleep(
        1000 * 2 ** attempt
      );
    }
  }

  throw (
    lastError ||
    new Error("Shopify request failed.")
  );
}

async function getAllProducts(
  shop,
  accessToken
) {
  const products = [];

  let after = null;
  let hasNextPage = true;

  const query = `
    query GetProducts($after: String) {
      products(first: 100, after: $after) {
        nodes {
          id
          title
          handle
          descriptionHtml

          seo {
            title
            description
          }

          options {
            id
            name
            position

            optionValues(first: 100) {
              nodes {
                id
                name
              }
            }
          }

          metafields(
            first: 20
            namespace: "maison_levara"
          ) {
            nodes {
              namespace
              key
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

  while (hasNextPage) {
    const data = await shopifyGraphQL(
      shop,
      accessToken,
      query,
      {
        after,
      }
    );

    products.push(
      ...data.products.nodes
    );

    hasNextPage =
      data.products.pageInfo.hasNextPage;

    after =
      data.products.pageInfo.endCursor;
  }

  return products;
}

// Franse voornamen voor de productnaamstructuur.
// Vorm: Voornaam | Productomschrijving
const FRENCH_FIRST_NAMES = [
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
  "Priscille",
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

const FRENCH_NAME_KEYS = new Set(
  FRENCH_FIRST_NAMES.map(normalize)
);

function fallbackFirstName(
  reservedTitles,
  seed
) {
  for (
    let offset = 0;
    offset < FRENCH_FIRST_NAMES.length;
    offset++
  ) {
    const name =
      FRENCH_FIRST_NAMES[
        (seed + offset) %
          FRENCH_FIRST_NAMES.length
      ];

    const prefix =
      `${normalize(name)} `;

    const used = [...reservedTitles].some(
      (title) =>
        normalize(title).startsWith(prefix)
    );

    if (!used) {
      return name;
    }
  }

  return (
    FRENCH_FIRST_NAMES[
      seed %
        FRENCH_FIRST_NAMES.length
    ]
  );
}

function protectHtml(html) {
  const tags = [];

  const protectedHtml =
    String(html || "").replace(
      /<[^>]*>/g,
      (tag) => {
        const token =
          `__ML_TAG_${String(tags.length).padStart(5, "0")}__`;

        tags.push({
          token,
          tag,
        });

        return token;
      }
    );

  return {
    protectedHtml,
    tags,
  };
}

function restoreHtml(
  translated,
  tags
) {
  let result =
    String(translated || "");

  for (const { token, tag } of tags) {
    const count =
      result.split(token).length - 1;

    if (count !== 1) {
      throw new Error(
        `HTML-structuur beschadigd: ${token} kwam ${count} keer terug.`
      );
    }

    result =
      result.replace(token, tag);
  }

  if (
    /__ML_TAG_\d{5}__/.test(result)
  ) {
    throw new Error(
      "Onvertaalde HTML-placeholder gevonden."
    );
  }

  return result;
}

function buildTitle(
  firstName,
  descriptor
) {
  const first =
    String(firstName || "")
      .replace(/\|/g, " ")
      .trim();

  const desc =
    String(descriptor || "")
      .replace(/\|/g, " ")
      .trim();

  return `${first} | ${desc}`;
}

function isAlreadyTranslated(
  product
) {
  return product.metafields.nodes.some(
    (metafield) =>
      metafield.namespace ===
        "maison_levara" &&
      metafield.key ===
        "fr_translation_v1" &&
      metafield.value === "done"
  );
}

function productInputForAI(
  product
) {
  const protectedDescription =
    protectHtml(
      product.descriptionHtml || ""
    );

  return {
    productId: product.id,

    currentTitle:
      product.title,

    descriptionHtml:
      protectedDescription.protectedHtml,

    htmlPlaceholders:
      protectedDescription.tags.map(
        (item) => item.token
      ),

    seo: {
      title:
        product.seo?.title || "",

      description:
        product.seo?.description || "",
    },

    options:
      product.options.map(
        (option, index) => ({
          index,

          id:
            option.id,

          name:
            option.name,

          values:
            option.optionValues.nodes.map(
              (value) => ({
                id:
                  value.id,

                name:
                  value.name,
              })
            ),
        })
      ),
  };
}

const AI_INSTRUCTIONS = `
Je bent de vaste Franse e-commerce copywriter
van Maison Lévara Paris.

Vertaal de aangeleverde productdata naar
natuurlijk, professioneel Frans voor een
moderne Franse modewebshop.

==============================
PRODUCTNAAM
==============================

Gebruik exact deze structuur:

"FranseVoornaam | Franse productomschrijving"

De eerste helft moet een echte Franse
voornaam zijn.

De tweede helft moet een korte, natuurlijke
Franse omschrijving van het producttype zijn.

Gebruik geen Nederlandse, Engelse, Italiaanse
of Spaanse productnamen.

Gebruik geen overdreven marketingtaal.

De stijl moet aansluiten op een Europese
fashionstore zoals de oude Luno Milano-structuur:
een voornaam, dan " | ", dan een duidelijke
productomschrijving.

==============================
BESCHRIJVING
==============================

Vertaal alle klantzichtbare tekst naar Frans.

Vertaal ook tekst binnen maattabellen.

Behandel de maattabel als normale klantzichtbare
productinhoud.

Behoud:
- HTML-structuur
- HTML-placeholders
- links
- afbeeldingen
- URLs
- classes
- ids
- data-attributen
- cijfers
- percentages
- afmetingen
- eenheden

Wijzig geen URL's.

Voeg geen HTML-tags toe.

Verwijder geen HTML-tags.

De meegeleverde HTML-placeholders moeten
exact behouden blijven en ieder exact één keer
terugkomen.

Behoud XS, S, M, L, XL, XXL, 2XL enzovoort.

Vertaal "One Size" als "Taille unique".

Vertaal kleurwaarden naar natuurlijk Frans.

Vertaal optie-namen zoals:
Size -> Taille
Color -> Couleur
Material -> Matière

Vertaal ook gewone taalwaarden van opties.

==============================
SEO
==============================

Vertaal SEO title naar natuurlijk Frans.

Houd SEO title waar praktisch rond maximaal
60 tekens.

Vertaal SEO description naar natuurlijk Frans.

Houd SEO description waar praktisch rond
150-160 tekens.

==============================
OPTIES
==============================

Geef voor iedere bestaande optie exact dezelfde
index terug.

Geef iedere bestaande option value exact
dezelfde id terug.

Vertaal option names.

Vertaal gewone taalwaarden.

Laat gestandaardiseerde maatcodes en numerieke
maten intact.

==============================
UNIEKE PRODUCTNAMEN
==============================

De volledige Franse producttitel moet uniek
zijn binnen de volledige catalogus.

Gebruik nooit een titel uit de lijst met reeds
bestaande catalogustitels.

Gebruik ook nooit een titel die door een andere
worker al is gereserveerd.

De uiteindelijke titel moet altijd zijn:

"FranseVoornaam | Franse productomschrijving"

Geef uitsluitend JSON volgens het schema.
`;

const AI_SCHEMA = {
  type: "object",

  additionalProperties: false,

  properties: {
    firstName: {
      type: "string",
    },

    descriptor: {
      type: "string",
    },

    descriptionHtml: {
      type: "string",
    },

    seoTitle: {
      type: "string",
    },

    seoDescription: {
      type: "string",
    },

    options: {
      type: "array",

      items: {
        type: "object",

        additionalProperties: false,

        properties: {
          index: {
            type: "integer",
          },

          name: {
            type: "string",
          },

          values: {
            type: "array",

            items: {
              type: "object",

              additionalProperties: false,

              properties: {
                id: {
                  type: "string",
                },

                name: {
                  type: "string",
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
  },

  required: [
    "firstName",
    "descriptor",
    "descriptionHtml",
    "seoTitle",
    "seoDescription",
    "options",
  ],
};

function openAIText(body) {
  if (
    typeof body.output_text ===
    "string"
  ) {
    return body.output_text;
  }

  for (
    const item of
    Array.isArray(body.output)
      ? body.output
      : []
  ) {
    for (
      const content of
      Array.isArray(item.content)
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
  if (!OPENAI_API_KEY) {
    throw new Error(
      "OPENAI_API_KEY ontbreekt in Render."
    );
  }

  let lastError = null;

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
          150000
        );

      const response =
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
                `Bearer ${OPENAI_API_KEY}`,
            },

            body: JSON.stringify({
              model:
                OPENAI_MODEL,

              store: false,

              input: [
                {
                  role: "system",

                  content: [
                    {
                      type:
                        "input_text",

                      text:
                        AI_INSTRUCTIONS,
                    },
                  ],
                },

                {
                  role: "user",

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

              text: {
                format: {
                  type:
                    "json_schema",

                  name:
                    "maison_levara_translation",

                  strict: true,

                  schema:
                    AI_SCHEMA,
                },
              },
            }),
          }
        );

      clearTimeout(timeout);

      const body =
        await response.json();

      if (
        response.status === 429
      ) {
        lastError =
          new Error(
            "OpenAI rate limit."
          );

        await sleep(
          1500 * 2 ** attempt
        );

        continue;
      }

      if (!response.ok) {
        throw new Error(
          `OpenAI HTTP ${response.status}: ${JSON.stringify(body)}`
        );
      }

      const text =
        openAIText(body);

      if (!text) {
        throw new Error(
          "OpenAI gaf geen resultaat terug."
        );
      }

      return JSON.parse(text);
    } catch (error) {
      lastError = error;

      if (attempt === 4) {
        break;
      }

      await sleep(
        1500 * 2 ** attempt
      );
    }
  }

  throw (
    lastError ||
    new Error(
      "OpenAI request failed."
    )
  );
}

async function makeTranslation(
  product,
  reservedTitles,
  index
) {
  const originalTags =
    protectHtml(
      product.descriptionHtml || ""
    ).tags;

  let previousTitle = "";

  for (
    let attempt = 0;
    attempt < 5;
    attempt++
  ) {
    const payload =
      productInputForAI(
        product
      );

    payload.existingTitles =
      [...reservedTitles]
        .slice(0, 100);

    payload.retryInstruction =
      previousTitle
        ? `Deze titel was al bezet: "${previousTitle}". Kies beslist een andere Franse titel.`
        : "";

    const result =
      await openAIJson(
        payload
      );

    let firstName =
      String(
        result.firstName || ""
      ).trim();

    if (
      !FRENCH_NAME_KEYS.has(
        normalize(firstName)
      )
    ) {
      firstName =
        fallbackFirstName(
          reservedTitles,
          index + attempt
        );
    }

    const title =
      buildTitle(
        firstName,
        result.descriptor
      );

    const key =
      normalize(title);

    if (
      !result.descriptor?.trim() ||
      !title.includes("|") ||
      reservedTitles.has(key)
    ) {
      previousTitle = title;
      continue;
    }

    // Reserve immediately so another worker
    // cannot generate the same product title.
    reservedTitles.add(key);

    const descriptionHtml =
      restoreHtml(
        result.descriptionHtml,
        originalTags
      );

    return {
      title,

      descriptionHtml,

      seoTitle:
        String(
          result.seoTitle || ""
        ).trim(),

      seoDescription:
        String(
          result.seoDescription || ""
        ).trim(),

      options:
        Array.isArray(
          result.options
        )
          ? result.options
          : [],
    };
  }

  throw new Error(
    `Geen unieke Franse productnaam gevonden voor: ${product.title}`
  );
}

async function updateProduct(
  shop,
  accessToken,
  product,
  translation
) {
  // 1. Producttitel, beschrijving en SEO.
  const productMutation = `
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
          handle
        }
      }
    }
  `;

  const productData =
    await shopifyGraphQL(
      shop,
      accessToken,
      productMutation,
      {
        product: {
          id:
            product.id,

          title:
            translation.title,

          descriptionHtml:
            translation.descriptionHtml,

          seo: {
            title:
              translation.seoTitle,

            description:
              translation.seoDescription,
          },
        },
      }
    );

  const errors =
    productData.productUpdate
      .userErrors || [];

  if (errors.length) {
    throw new Error(
      errors
        .map(
          (error) =>
            error.message
        )
        .join(" | ")
    );
  }

  // 2. Productopties zoals Size/Color.
  for (
    const option of product.options
  ) {
    const translated =
      translation.options.find(
        (item) =>
          Number(
            item.index
          ) ===
          Number(
            option.position - 1
          )
      );

    if (!translated) {
      continue;
    }

    const optionValuesToUpdate =
      option.optionValues.nodes
        .map(
          (original) => {
            const match =
              translated.values?.find(
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
                match.name || ""
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

              name,
            };
          }
        )
        .filter(Boolean);

    const translatedOptionName =
      String(
        translated.name || ""
      ).trim();

    const optionNameChanged =
      translatedOptionName &&
      translatedOptionName !==
        option.name.trim();

    if (
      !optionNameChanged &&
      optionValuesToUpdate.length ===
        0
    ) {
      continue;
    }

    // Shopify gebruikt hier expliciet
    // optionValuesToUpdate.
    const optionMutation = `
      mutation UpdateOption(
        $productId: ID!,
        $option: OptionUpdateInput!,
        $optionValuesToUpdate: [OptionValueUpdateInput!]
      ) {
        productOptionUpdate(
          productId: $productId,
          option: $option,
          optionValuesToUpdate: $optionValuesToUpdate,
          variantStrategy: LEAVE_AS_IS
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

    const optionData =
      await shopifyGraphQL(
        shop,
        accessToken,
        optionMutation,
        {
          productId:
            product.id,

          option: {
            id:
              option.id,

            name:
              translatedOptionName ||
              option.name,

            position:
              option.position,
          },

          optionValuesToUpdate,
        }
      );

    const optionErrors =
      optionData
        .productOptionUpdate
        .userErrors || [];

    if (optionErrors.length) {
      throw new Error(
        optionErrors
          .map(
            (error) =>
              error.message
          )
          .join(" | ")
      );
    }
  }
}

async function markDone(
  shop,
  accessToken,
  productId
) {
  const mutation = `
    mutation MarkTranslated(
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
      accessToken,
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

  if (errors.length) {
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

async function runTranslationJob(
  shop
) {
  const connection =
    shopTokens.get(shop);

  if (!connection) {
    throw new Error(
      "Shopify is niet verbonden."
    );
  }

  job.running = true;
  job.shop = shop;
  job.total = 0;
  job.pending = 0;
  job.processed = 0;
  job.skipped = 0;
  job.failed = 0;
  job.current = null;
  job.startedAt =
    new Date().toISOString();
  job.finishedAt = null;
  job.errors = [];
  job.logs = [];

  try {
    addLog(
      "Productcatalogus ophalen..."
    );

    const products =
      await getAllProducts(
        shop,
        connection.accessToken
      );

    job.total =
      products.length;

    // Alle huidige titels worden gereserveerd.
    // Een nieuw Frans product mag nooit
    // exact dezelfde titel krijgen.
    const reservedTitles =
      new Set(
        products
          .map(
            (product) =>
              normalize(
                product.title
              )
          )
          .filter(Boolean)
      );

    const pending =
      products.filter(
        (product) =>
          !isAlreadyTranslated(
            product
          )
      );

    job.pending =
      pending.length;

    job.skipped =
      products.length -
      pending.length;

    addLog(
      `${products.length} producten gevonden.`
    );

    addLog(
      `${pending.length} producten moeten nog vertaald worden.`
    );

    let cursor = 0;

    async function worker(
      workerId
    ) {
      while (true) {
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

          title:
            product.title,
        };

        try {
          addLog(
            `Start ${index + 1}/${pending.length}: ${product.title}`
          );

          const translation =
            await makeTranslation(
              product,
              reservedTitles,
              index
            );

          addLog(
            `Nieuwe naam: ${translation.title}`
          );

          await updateProduct(
            shop,
            connection.accessToken,
            product,
            translation
          );

          // Alleen wanneer alle updates
          // gelukt zijn, markeren als klaar.
          await markDone(
            shop,
            connection.accessToken,
            product.id
          );

          job.processed++;

          addLog(
            `Klaar: ${translation.title}`
          );
        } catch (error) {
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

          addLog(
            `FOUT: ${message}`
          );
        } finally {
          job.current = null;
        }
      }
    }

    // Drie workers voor snelheid zonder
    // onnodig agressieve paralleliteit.
    await Promise.all([
      worker(1),
      worker(2),
      worker(3),
    ]);

    addLog(
      `VERTAALJOB KLAAR — ${job.processed} verwerkt, ${job.skipped} overgeslagen, ${job.failed} fouten.`
    );
  } catch (error) {
    job.failed++;

    job.errors.push(
      error.message
    );

    addLog(
      `JOB FOUT: ${error.message}`
    );
  } finally {
    job.running = false;
    job.current = null;
    job.finishedAt =
      new Date().toISOString();
  }
}

app.get(
  "/",
  (req, res) => {
    res.send(`
      <h1>Maison Lévara Paris</h1>
      <p>Shopify API connection is online.</p>
    `);
  }
);

app.get(
  "/health",
  (req, res) => {
    res.json({
      ok: true,

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

      shopifyApiVersion:
        SHOPIFY_API_VERSION,
    });
  }
);

app.get(
  "/auth",
  (req, res) => {
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
        .randomBytes(24)
        .toString("hex");

    oauthStates.set(
      state,
      {
        shop,

        expiresAt:
          Date.now() +
          10 * 60 * 1000,
      }
    );

    const url =
      `https://${shop}/admin/oauth/authorize?` +
      new URLSearchParams({
        client_id:
          CLIENT_ID,

        scope:
          SHOPIFY_SCOPES,

        redirect_uri:
          REDIRECT_URI,

        state,
      }).toString();

    res.redirect(url);
  }
);

app.get(
  "/auth/callback",
  async (req, res) => {
    const {
      code,
      shop,
      state,
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
      saved.shop !== shop ||
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
                  CLIENT_ID,

                client_secret:
                  CLIENT_SECRET,

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
        console.error(
          data
        );

        return res
          .status(500)
          .send(
            "Shopify token-uitwisseling mislukt."
          );
      }

      shopTokens.set(
        shop,
        {
          accessToken:
            data.access_token,

          scope:
            data.scope,
        }
      );

      const sessionId =
        createSession(
          shop
        );

      res.setHeader(
        "Set-Cookie",
        `ml_session=${encodeURIComponent(
          sessionId
        )}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`
      );

      res.send(`
        <h1>Shopify succesvol verbonden!</h1>
        <p>Shop: ${shop}</p>
        <p>Scope: ${data.scope}</p>
        <p>
          <a href="/admin?shop=${encodeURIComponent(
            shop
          )}">
            Open vertaalbeheer
          </a>
        </p>
      `);
    } catch (error) {
      console.error(
        error
      );

      res
        .status(500)
        .send(
          "Er ging iets mis met de Shopify-verbinding."
        );
    }
  }
);

app.get(
  "/products",
  async (req, res) => {
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

    const connection =
      shopTokens.get(
        shop
      );

    if (!connection) {
      return res
        .status(401)
        .send(
          "Shopify is nog niet verbonden."
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

        products:
          products.slice(
            0,
            10
          ).map(
            (product) => ({
              id:
                product.id,

              title:
                product.title,

              handle:
                product.handle,

              options:
                product.options.map(
                  (option) => ({
                    name:
                      option.name,

                    values:
                      option.optionValues.nodes.map(
                        (value) =>
                          value.name
                      ),
                  })
                ),
            })
          ),
      });
    } catch (error) {
      console.error(
        error
      );

      res
        .status(500)
        .json({
          error:
            error.message,
        });
    }
  }
);

app.get(
  "/admin",
  (req, res) => {
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
      sessionShop(req) !==
      shop
    ) {
      return res
        .status(403)
        .send(
          "Geen geldige Shopify-sessie. Open eerst /auth?shop=..."
        );
    }

    res.send(`
<!doctype html>

<html lang="nl">

<head>

<meta charset="utf-8">

<meta
  name="viewport"
  content="width=device-width,initial-scale=1"
>

<title>
  Maison Lévara —
  Franse vertaling
</title>

<style>

body{
  font-family:
    Arial,
    sans-serif;

  max-width:
    950px;

  margin:
    40px auto;

  padding:
    0 20px;

  color:
    #111;
}

button{
  background:
    #111;

  color:
    #fff;

  border:
    0;

  padding:
    14px 22px;

  border-radius:
    7px;

  cursor:
    pointer;

  font-size:
    16px;
}

button:disabled{
  opacity:
    .5;

  cursor:
    not-allowed;
}

.card{
  padding:
    20px;

  background:
    #f5f5f5;

  border-radius:
    10px;

  margin:
    18px 0;
}

pre{
  white-space:
    pre-wrap;

  background:
    #111;

  color:
    #eee;

  padding:
    15px;

  border-radius:
    8px;

  max-height:
    520px;

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

<p>
  Shop:
  <strong>
    ${shop}
  </strong>
</p>

<div class="card">

<p>
  Deze job verwerkt
  alle nog niet vertaalde producten.
</p>

<p>
  Prijzen, voorraad,
  SKU's, afbeeldingen
  en handles worden
  niet gewijzigd.
</p>

<p>
  Producttitels worden
  uniek gegenereerd in
  de structuur:
  <strong>
    Franse voornaam |
    Franse productomschrijving
  </strong>
</p>

<button id="start">
  Start Franse vertaling
</button>

</div>

<div
  class="card"
  id="status"
>
  Status laden...
</div>

<h3>
  Log
</h3>

<pre id="logs">
Wachten...
</pre>

<script>

const shop =
  ${JSON.stringify(shop)};

const start =
  document.getElementById(
    "start"
  );

async function refresh() {

  try {

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
              " — " +
              data.current.title
            )
          : ""
      );

    document.getElementById(
      "logs"
    ).textContent =
      (
        data.logs || []
      ).join(
        "\\n"
      );

    start.disabled =
      data.running;

  } catch (error) {

    console.error(
      error
    );

  }
}

start.onclick =
  async () => {

    start.disabled =
      true;

    const response =
      await fetch(
        "/translate-all",
        {
          method:
            "POST",

          headers: {
            "Content-Type":
              "application/json",
          },

          body:
            JSON.stringify({
              shop,
            }),
        }
      );

    const data =
      await response.json();

    if (!response.ok) {

      alert(
        data.error ||
        "Starten mislukt."
      );

      start.disabled =
        false;

      return;
    }

    alert(
      "Vertaaljob gestart. Laat dit tabblad open."
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
`);
  }
);

app.post(
  "/translate-all",
  async (req, res) => {
    const shop =
      req.body?.shop;

    if (
      !validShop(shop)
    ) {
      return res
        .status(400)
        .json({
          error:
            "Ongeldige shop.",
        });
    }

    if (
      sessionShop(req) !==
      shop
    ) {
      return res
        .status(403)
        .json({
          error:
            "Geen geldige Shopify-sessie.",
        });
    }

    if (
      job.running
    ) {
      return res
        .status(409)
        .json({
          error:
            "Er draait al een vertaaljob.",
        });
    }

    if (
      !shopTokens.has(
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
            "OPENAI_API_KEY ontbreekt in Render.",
        });
    }

    runTranslationJob(
      shop
    ).catch(
      (error) => {
        addLog(
          `Onverwachte job-fout: ${error.message}`
        );
      }
    );

    res
      .status(202)
      .json({
        ok: true,
      });
  }
);

app.get(
  "/translate-status",
  (req, res) => {
    const shop =
      req.query.shop;

    if (
      sessionShop(req) !==
      shop
    ) {
      return res
        .status(403)
        .json({
          error:
            "Geen geldige Shopify-sessie.",
        });
    }

    res.json({
      running:
        job.running,

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
        ),
    });
  }
);

if (
  typeof fetch !==
  "function"
) {
  throw new Error(
    "Deze server vereist Node.js 18 of nieuwer."
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
