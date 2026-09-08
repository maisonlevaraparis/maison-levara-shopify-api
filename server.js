const express = require("express");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;
const CLIENT_ID = process.env.SHOPIFY_CLIENT_ID;
const CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;

const SHOPIFY_API_VERSION = "2026-07";
const OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-5";

const SCOPES = "write_products";

// Shopify OAuth/token opslag.
// Dit blijft in geheugen bestaan zolang de Render instance draait.
const states = new Map();
const tokens = new Map();
const sessions = new Map();

// Eén vertaaljob tegelijk.
const job = {
  running: false,
  shop: null,
  total: 0,
  processed: 0,
  skipped: 0,
  failed: 0,
  current: null,
  startedAt: null,
  finishedAt: null,
  errors: [],
  logs: []
};

app.use(express.json({ limit: "2mb" }));
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

function normalizeName(value) {
  return String(value || "")
    .normalize("NFD")
    .replace(/\p{Diacritic}/gu, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim();
}

function addLog(message) {
  const line = `[${new Date().toISOString()}] ${message}`;
  job.logs.push(line);

  if (job.logs.length > 150) {
    job.logs.shift();
  }

  console.log(line);
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  const result = {};

  for (const part of header.split(";")) {
    const index = part.indexOf("=");

    if (index === -1) continue;

    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    result[key] = decodeURIComponent(value);
  }

  return result;
}

function createSession(shop) {
  const token = crypto.randomBytes(32).toString("hex");

  sessions.set(token, {
    shop,
    expiresAt: Date.now() + 24 * 60 * 60 * 1000
  });

  return token;
}

function getSessionShop(req) {
  const cookies = parseCookies(req);
  const sessionToken = cookies.ml_session;

  if (!sessionToken) return null;

  const session = sessions.get(sessionToken);

  if (!session) return null;

  if (session.expiresAt < Date.now()) {
    sessions.delete(sessionToken);
    return null;
  }

  return session.shop;
}

function verifyHmac(query) {
  const { hmac, ...params } = query;

  if (!hmac || !CLIENT_SECRET) return false;

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

async function shopifyGraphQL(shop, accessToken, query, variables = {}) {
  let lastError;

  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      const response = await fetch(
        `https://${shop}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Shopify-Access-Token": accessToken
          },
          body: JSON.stringify({
            query,
            variables
          })
        }
      );

      const body = await response.json();

      if (response.status === 429) {
        lastError = new Error("Shopify rate limit");

        await sleep(1000 * Math.pow(2, attempt));
        continue;
      }

      if (!response.ok) {
        throw new Error(
          `Shopify HTTP ${response.status}: ${JSON.stringify(body)}`
        );
      }

      if (body.errors && body.errors.length) {
        const message = body.errors
          .map((error) => error.message)
          .join(" | ");

        if (/throttl/i.test(message)) {
          lastError = new Error(message);

          await sleep(1000 * Math.pow(2, attempt));
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

      await sleep(1000 * Math.pow(2, attempt));
    }
  }

  throw lastError || new Error("Shopify request failed");
}

async function getAllProducts(shop, accessToken) {
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

          metafields(first: 10, namespace: "maison_levara") {
            nodes {
              namespace
              key
              value
            }
          }

          variants(first: 250) {
            nodes {
              id
              title
              selectedOptions {
                name
                value
              }
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
      { after }
    );

    const connection = data.products;

    products.push(...connection.nodes);

    hasNextPage = connection.pageInfo.hasNextPage;
    after = connection.pageInfo.endCursor;
  }

  return products;
}

const FRENCH_NAMES = [
  "Adèle",
  "Agathe",
  "Agnès",
  "Aïcha",
  "Alix",
  "Amélie",
  "Anaïs",
  "Andréa",
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
  "Élodie",
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
  "Zoé"
];

const FRENCH_NAME_KEYS = new Set(
  FRENCH_NAMES.map(normalizeName)
);

function pickFrenchName(preferredName, reservedTitles) {
  const preferredKey = normalizeName(preferredName);

  if (preferredKey && FRENCH_NAME_KEYS.has(preferredKey)) {
    return preferredName;
  }

  const unused = FRENCH_NAMES.find(
    (name) => !reservedTitles.has(
      normalizeName(`${name} |`)
    )
  );

  return unused || FRENCH_NAMES[0];
}

function tagSkeleton(html) {
  return [...String(html || "").matchAll(
    /<\s*(\/?)\s*([a-zA-Z0-9]+)/g
  )].map((match) => `${match[1] ? "/" : ""}${match[2].toLowerCase()}`);
}

function resourceUrls(html) {
  return [...String(html || "").matchAll(
    /\b(?:href|src)\s*=\s*["']([^"']+)["']/gi
  )]
    .map((match) => match[1])
    .sort();
}

function sameArray(a, b) {
  return (
    a.length === b.length &&
    a.every((value, index) => value === b[index])
  );
}

function htmlStructureIsSafe(originalHtml, translatedHtml) {
  if (!originalHtml && !translatedHtml) {
    return true;
  }

  if (!translatedHtml) {
    return false;
  }

  return (
    sameArray(
      tagSkeleton(originalHtml),
      tagSkeleton(translatedHtml)
    ) &&
    sameArray(
      resourceUrls(originalHtml),
      resourceUrls(translatedHtml)
    )
  );
}

function extractResponseText(body) {
  if (typeof body.output_text === "string") {
    return body.output_text;
  }

  const output = Array.isArray(body.output)
    ? body.output
    : [];

  for (const item of output) {
    if (!Array.isArray(item.content)) continue;

    for (const content of item.content) {
      if (
        content &&
        typeof content.text === "string"
      ) {
        return content.text;
      }
    }
  }

  return "";
}

async function openAIJson(instructions, payload) {
  if (!OPENAI_API_KEY) {
    throw new Error("OPENAI_API_KEY ontbreekt in Render.");
  }

  let lastError;

  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      const controller = new AbortController();

      const timeout = setTimeout(
        () => controller.abort(),
        120000
      );

      const response = await fetch(
        "https://api.openai.com/v1/responses",
        {
          method: "POST",
          signal: controller.signal,
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${OPENAI_API_KEY}`
          },
          body: JSON.stringify({
            model: OPENAI_MODEL,
            store: false,

            input: [
              {
                role: "system",
                content: [
                  {
                    type: "input_text",
                    text: instructions
                  }
                ]
              },
              {
                role: "user",
                content: [
                  {
                    type: "input_text",
                    text: JSON.stringify(payload)
                  }
                ]
              }
            ],

            text: {
              format: {
                type: "json_schema",
                name: "product_translation",
                strict: true,
                schema: {
                  type: "object",
                  additionalProperties: false,
                  properties: {
                    firstName: {
                      type: "string"
                    },

                    descriptor: {
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
                    }
                  },
                  required: [
                    "firstName",
                    "descriptor",
                    "descriptionHtml",
                    "seoTitle",
                    "seoDescription",
                    "options"
                  ]
                }
              }
            }
          })
        }
      );

      clearTimeout(timeout);

      const body = await response.json();

      if (response.status === 429) {
        lastError = new Error("OpenAI rate limit.");

        await sleep(
          1500 * Math.pow(2, attempt)
        );

        continue;
      }

      if (!response.ok) {
        throw new Error(
          `OpenAI HTTP ${response.status}: ${JSON.stringify(body)}`
        );
      }

      if (body.error) {
        throw new Error(
          body.error.message || "OpenAI fout."
        );
      }

      const text = extractResponseText(body);

      if (!text) {
        throw new Error(
          "OpenAI gaf geen tekstresultaat terug."
        );
      }

      return JSON.parse(text);
    } catch (error) {
      lastError = error;

      if (attempt === 4) {
        break;
      }

      await sleep(
        1500 * Math.pow(2, attempt)
      );
    }
  }

  throw lastError || new Error("OpenAI request failed");
}

const TRANSLATION_INSTRUCTIONS = `
Je bent de vaste Franse e-commerce copywriter en productdata-editor van Maison Lévara Paris.

VERTAAL ALLE KLANTZICHTBARE PRODUCTINHOUD NAAR NATUURLIJK, VERZORGD FRANS.

NAMENSTRUCTUUR:
Gebruik exact dezelfde stijl als een moderne Europese fashionstore:
"Voornaam | Producttype / productomschrijving"

Voorbeelden van de stijl:
"Alessia | Veste d'hiver"
"Carlotte | Robe décontractée fluide"

De voornaam MOET een echte Franse voornaam zijn.
Gebruik geen Engelse, Nederlandse, Italiaanse of Spaanse voornaam.

De descriptor na "|" moet:
- Frans zijn
- natuurlijk klinken
- duidelijk maken wat het product is
- compact blijven
- niet overdreven SEO-achtig zijn
- passen bij dames-, heren-, schoenen-, accessoires- of andere modeproducten

BELANGRIJK OVER DE BESCHRIJVING:
- Vertaal alle zichtbare tekst naar Frans.
- Vertaal ook tekst in HTML-attributen zoals alt/title wanneer dat gewone menselijke tekst is.
- Behoud exact dezelfde HTML-structuur.
- Verwijder geen tags.
- Voeg geen nieuwe tags toe.
- Wijzig nooit href-URL's.
- Wijzig nooit src-URL's.
- Behoud classes, ids en data-* attributen.
- Behoud links en afbeeldingen.
- Behoud tabellen exact qua structuur.
- Vertaald de tekst IN maattabellen volledig naar Frans.
- Behoud cijfers, maten, afmetingen en eenheden.
- Behoud productcodes, SKU-achtige codes, modelcodes en technische codes.
- XS, S, M, L, XL, XXL en numerieke maten mogen niet onnodig veranderd worden.
- "One Size" mag natuurlijk naar "Taille unique".
- Kleuren moeten naar natuurlijk Frans worden vertaald.
- Maatopties moeten naar Frans worden vertaald, bijvoorbeeld "Size" → "Taille".
- Color → "Couleur".
- Material → "Matière".
- Gebruik Franse fashionterminologie.

SEO:
- SEO title: natuurlijk Frans, maximaal ongeveer 60 tekens.
- SEO description: natuurlijk Frans, ongeveer 150-160 tekens.
- Geen keyword stuffing.

OPTIES:
Vertaal de namen van productopties.
Vertaal de waarden van productopties wanneer het gewone taal betreft.
Behoud gestandaardiseerde maatcodes en numerieke waarden.
Kleurwaarden altijd natuurlijk Frans maken.

GEEF ALLEEN HET GEVRAAGDE JSON-OBJECT TERUG.
`;

function buildProductPayload(product) {
  return {
    product: {
      id: product.id,
      currentTitle: product.title,
      descriptionHtml: product.descriptionHtml || "",
      seo: {
        title: product.seo?.title || "",
        description: product.seo?.description || ""
      },

      options: product.options.map(
        (option, index) => ({
          index,
          id: option.id,
          name: option.name,
          values: option.optionValues.nodes.map(
            (value) => ({
              id: value.id,
              name: value.name
            })
          )
        })
      ),

      variants: product.variants.nodes.map(
        (variant) => ({
          id: variant.id,
          title: variant.title,
          selectedOptions: variant.selectedOptions
        })
      )
    }
  };
}

function buildTitle(firstName, descriptor) {
  const cleanFirstName = String(firstName || "")
    .replace(/\|/g, "")
    .trim();

  const cleanDescriptor = String(descriptor || "")
    .replace(/\|/g, "")
    .trim();

  return `${cleanFirstName} | ${cleanDescriptor}`;
}

async function generateTranslation(product, reservedTitles) {
  let lastCandidate = null;

  for (let attempt = 0; attempt < 4; attempt++) {
    const extraInstruction = lastCandidate
      ? `
De voorgestelde productnaam hieronder is afgewezen omdat die niet uniek was:
"${lastCandidate}"

Kies daarom absoluut een andere Franse voornaam en/of descriptor.
`
      : "";

    const prompt = `${TRANSLATION_INSTRUCTIONS}

${extraInstruction}

Maak een nieuwe Franse producttitel volgens de structuur:
"FranseVoornaam | Franse productomschrijving"

De volledige producttitel mag nergens anders in de catalogus voorkomen.

Hier is de productdata:
`;

    const result = await openAIJson(
      prompt,
      buildProductPayload(product)
    );

    let firstName = result.firstName;
    let descriptor = result.descriptor;

    if (!FRENCH_NAME_KEYS.has(normalizeName(firstName))) {
      firstName = pickFrenchName(
        firstName,
        reservedTitles
      );
    }

    const title = buildTitle(
      firstName,
      descriptor
    );

    const titleKey = normalizeName(title);

    if (
      !titleKey ||
      !descriptor ||
      !title.includes("|")
    ) {
      lastCandidate = title;
      continue;
    }

    if (
      reservedTitles.has(titleKey) ||
      normalizeName(product.title) === titleKey
    ) {
      lastCandidate = title;
      continue;
    }

    if (
      !htmlStructureIsSafe(
        product.descriptionHtml || "",
        result.descriptionHtml || ""
      )
    ) {
      throw new Error(
        "OpenAI veranderde de HTML-structuur van de productbeschrijving."
      );
    }

    return {
      title,
      descriptionHtml: result.descriptionHtml,
      seoTitle: result.seoTitle,
      seoDescription: result.seoDescription,
      options: result.options || []
    };
  }

  throw new Error(
    `Geen unieke Franse productnaam kunnen genereren voor ${product.title}`
  );
}

async function updateProduct(shop, accessToken, product, translation) {
  const updateProductMutation = `
    mutation UpdateProduct($product: ProductUpdateInput!) {
      productUpdate(product: $product) {
        userErrors {
          field
          message
        }

        product {
          id
          title
          handle
          seo {
            title
            description
          }
        }
      }
    }
  `;

  const productInput = {
    id: product.id,
    title: translation.title,
    descriptionHtml: translation.descriptionHtml,
    seo: {
      title: translation.seoTitle,
      description: translation.seoDescription
    }
  };

  const productData = await shopifyGraphQL(
    shop,
    accessToken,
    updateProductMutation,
    {
      product: productInput
    }
  );

  const userErrors =
    productData.productUpdate.userErrors || [];

  if (userErrors.length) {
    throw new Error(
      userErrors
        .map((error) => error.message)
        .join(" | ")
    );
  }

  for (const option of product.options) {
    const translatedOption = translation.options.find(
      (item) => Number(item.index) === Number(option.position - 1)
    );

    if (!translatedOption) {
      continue;
    }

    const valueUpdates = [];

    for (const originalValue of option.optionValues.nodes) {
      const translatedValue =
        translatedOption.values.find(
          (value) =>
            String(value.id) ===
            String(originalValue.id)
        );

      if (!translatedValue) {
        continue;
      }

      if (
        String(translatedValue.name).trim() !==
        String(originalValue.name).trim()
      ) {
        valueUpdates.push({
          id: originalValue.id,
          name: translatedValue.name
        });
      }
    }

    const optionNameChanged =
      String(translatedOption.name).trim() !==
      String(option.name).trim();

    if (
      !optionNameChanged &&
      valueUpdates.length === 0
    ) {
      continue;
    }

    const optionMutation = `
      mutation UpdateProductOption(
        $productId: ID!,
        $option: OptionUpdateInput!,
        $values: [OptionValueUpdateInput!]
      ) {
        productOptionUpdate(
          productId: $productId,
          option: $option,
          optionValuesToUpdate: $values,
          variantStrategy: LEAVE_AS_IS
        ) {
          userErrors {
            field
            message
          }

          product {
            id
            options {
              id
              name
              position
              optionValues {
                id
                name
              }
            }
          }
        }
      }
    `;

    const optionData = await shopifyGraphQL(
      shop,
      accessToken,
      optionMutation,
      {
        productId: product.id,

        option: {
          id: option.id,
          name: translatedOption.name,
          position: option.position
        },

        values: valueUpdates
      }
    );

    const optionErrors =
      optionData.productOptionUpdate.userErrors || [];

    if (optionErrors.length) {
      throw new Error(
        optionErrors
          .map((error) => error.message)
          .join(" | ")
      );
    }
  }

  await markProductDone(
    shop,
    accessToken,
    product.id
  );
}

async function markProductDone(shop, accessToken, productId) {
  const mutation = `
    mutation MarkTranslated(
      $metafields: [MetafieldsSetInput!]!
    ) {
      metafieldsSet(
        metafields: $metafields
      ) {
        metafields {
          id
          namespace
          key
          value
        }

        userErrors {
          field
          message
          code
        }
      }
    }
  `;

  const data = await shopifyGraphQL(
    shop,
    accessToken,
    mutation,
    {
      metafields: [
        {
          ownerId: productId,
          namespace: "maison_levara",
          key: "fr_translation_v1",
          type: "single_line_text_field",
          value: "done"
        }
      ]
    }
  );

  const errors =
    data.metafieldsSet.userErrors || [];

  if (errors.length) {
    throw new Error(
      errors
        .map((error) => error.message)
        .join(" | ")
    );
  }
}

function alreadyTranslated(product) {
  return product.metafields.nodes.some(
    (item) =>
      item.namespace === "maison_levara" &&
      item.key === "fr_translation_v1" &&
      item.value === "done"
  );
}

async function processProduct(
  shop,
  accessToken,
  product,
  reservedTitles
) {
  addLog(
    `Start: ${product.title}`
  );

  const translation =
    await generateTranslation(
      product,
      reservedTitles
    );

  addLog(
    `Nieuwe naam: ${translation.title}`
  );

  await updateProduct(
    shop,
    accessToken,
    product,
    translation
  );

  reservedTitles.add(
    normalizeName(translation.title)
  );

  addLog(
    `Klaar: ${translation.title}`
  );
}

async function runTranslationJob(shop) {
  if (job.running) {
    return;
  }

  const connection = tokens.get(shop);

  if (!connection) {
    throw new Error(
      "Shopify is niet verbonden."
    );
  }

  job.running = true;
  job.shop = shop;
  job.processed = 0;
  job.skipped = 0;
  job.failed = 0;
  job.current = null;
  job.startedAt = new Date().toISOString();
  job.finishedAt = null;
  job.errors = [];
  job.logs = [];

  try {
    addLog("Productcatalogus ophalen...");

    const products = await getAllProducts(
      shop,
      connection.accessToken
    );

    job.total = products.length;

    addLog(
      `${products.length} producten gevonden.`
    );

    const reservedTitles = new Set(
      products.map((product) =>
        normalizeName(product.title)
      )
    );

    const pending = [];

    for (const product of products) {
      if (alreadyTranslated(product)) {
        job.skipped++;
        continue;
      }

      pending.push(product);
    }

    addLog(
      `${pending.length} producten moeten vertaald worden.`
    );

    let cursor = 0;

    async function worker(workerNumber) {
      while (true) {
        const index = cursor++;

        if (index >= pending.length) {
          return;
        }

        const product = pending[index];

        job.current = {
          worker: workerNumber,
          id: product.id,
          title: product.title
        };

        try {
          await processProduct(
            shop,
            connection.accessToken,
            product,
            reservedTitles
          );

          job.processed++;
        } catch (error) {
          job.failed++;

          const message =
            `${product.title}: ${error.message}`;

          job.errors.push(message);

          if (job.errors.length > 100) {
            job.errors.shift();
          }

          addLog(
            `FOUT: ${message}`
          );
        }

        job.current = null;
      }
    }

    // 4 gelijktijdige producten voor snelheid.
    await Promise.all([
      worker(1),
      worker(2),
      worker(3),
      worker(4)
    ]);

    addLog(
      `VERTAALJOB KLAAR — ${job.processed} verwerkt, ${job.skipped} overgeslagen, ${job.failed} fouten.`
    );
  } catch (error) {
    job.errors.push(error.message);
    addLog(`JOB FOUT: ${error.message}`);
  } finally {
    job.running = false;
    job.current = null;
    job.finishedAt = new Date().toISOString();
  }
}

// --------------------------------------------------
// HOME
// --------------------------------------------------

app.get("/", (req, res) => {
  res.send(`
    <h1>Maison Lévara Paris</h1>

    <p>Shopify API connection is online.</p>

    <p>
      Gebruik /auth?shop=xqc0k1-mg.myshopify.com
      om Shopify te verbinden.
    </p>
  `);
});

// --------------------------------------------------
// OAUTH START
// --------------------------------------------------

app.get("/auth", (req, res) => {
  const shop = req.query.shop;

  if (!validShop(shop)) {
    return res.status(400).send(
      "Ongeldige Shopify shop."
    );
  }

  if (
    !CLIENT_ID ||
    !CLIENT_SECRET ||
    !REDIRECT_URI
  ) {
    return res.status(500).send(
      "Shopify environment variables ontbreken."
    );
  }

  const state = crypto
    .randomBytes(16)
    .toString("hex");

  states.set(state, shop);

  const authUrl =
    `https://${shop}/admin/oauth/authorize?` +
    new URLSearchParams({
      client_id: CLIENT_ID,
      scope: SCOPES,
      redirect_uri: REDIRECT_URI,
      state
    }).toString();

  res.redirect(authUrl);
});

// --------------------------------------------------
// OAUTH CALLBACK
// --------------------------------------------------

app.get("/auth/callback", async (req, res) => {
  const {
    code,
    shop,
    state
  } = req.query;

  if (!validShop(shop)) {
    return res.status(400).send(
      "Ongeldige Shopify shop."
    );
  }

  if (
    !state ||
    states.get(state) !== shop
  ) {
    return res.status(403).send(
      "Ongeldige state."
    );
  }

  states.delete(state);

  if (!verifyHmac(req.query)) {
    return res.status(403).send(
      "Ongeldige Shopify HMAC."
    );
  }

  try {
    const response = await fetch(
      `https://${shop}/admin/oauth/access_token`,
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded"
        },

        body: new URLSearchParams({
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
          code
        })
      }
    );

    const data = await response.json();

    if (!response.ok) {
      console.error(data);

      return res.status(500).send(
        "Shopify token-uitwisseling mislukt."
      );
    }

    tokens.set(shop, {
      accessToken: data.access_token,
      scope: data.scope
    });

    const sessionToken =
      createSession(shop);

    res.setHeader(
      "Set-Cookie",
      `ml_session=${encodeURIComponent(sessionToken)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`
    );

    res.send(`
      <h1>Shopify succesvol verbonden!</h1>

      <p>Maison Lévara Paris is verbonden met Shopify.</p>

      <p>Shop: ${shop}</p>

      <p>Scope: ${data.scope}</p>

      <p>De API-verbinding werkt.</p>

      <hr>

      <p>
        <a href="/admin?shop=${encodeURIComponent(shop)}">
          Open vertaalbeheer
        </a>
      </p>
    `);
  } catch (error) {
    console.error(error);

    res.status(500).send(
      "Er ging iets mis met de verbinding met Shopify."
    );
  }
});

// --------------------------------------------------
// PRODUCT TEST / READ
// --------------------------------------------------

app.get("/products", async (req, res) => {
  const shop = req.query.shop;

  if (!validShop(shop)) {
    return res.status(400).send(
      "Ongeldige Shopify shop."
    );
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
    const data = await shopifyGraphQL(
      shop,
      connection.accessToken,
      query
    );

    res.json(data);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: error.message
    });
  }
});

// --------------------------------------------------
// ADMIN
// --------------------------------------------------

app.get("/admin", (req, res) => {
  const shop = req.query.shop;

  if (!validShop(shop)) {
    return res.status(400).send(
      "Ongeldige shop."
    );
  }

  const sessionShop = getSessionShop(req);

  if (sessionShop !== shop) {
    return res.status(403).send(
      "Geen geldige Shopify-sessie. Open eerst /auth?shop=..."
    );
  }

  res.send(`
    <!doctype html>

    <html lang="nl">

    <head>

      <meta charset="utf-8">

      <title>Maison Lévara — Franse vertaling</title>

      <meta name="viewport"
        content="width=device-width, initial-scale=1">

      <style>

        body {
          font-family: Arial, sans-serif;
          max-width: 900px;
          margin: 40px auto;
          padding: 0 20px;
        }

        button {
          background: #111;
          color: white;
          border: 0;
          padding: 14px 22px;
          border-radius: 6px;
          cursor: pointer;
          font-size: 16px;
        }

        .status {
          padding: 20px;
          background: #f3f3f3;
          border-radius: 8px;
          margin-top: 20px;
        }

        .danger {
          color: #a00000;
        }

        pre {
          white-space: pre-wrap;
          background: #111;
          color: #eee;
          padding: 15px;
          border-radius: 8px;
        }

      </style>

    </head>

    <body>

      <h1>Maison Lévara Paris</h1>

      <h2>Franse productvertaling</h2>

      <p>
        Winkel:
        <strong>${shop}</strong>
      </p>

      <p>
        De vertaler verandert alleen productinhoud,
        productopties en SEO.
      </p>

      <p>
        Prijzen, SKU's, voorraad, afbeeldingen en handles
        worden niet aangepast.
      </p>

      <button id="start">
        Start Franse vertaling
      </button>

      <div class="status">

        <div id="status">
          Status laden...
        </div>

      </div>

      <h3>Log</h3>

      <pre id="logs">Wachten...</pre>

      <script>

        const shop =
          ${JSON.stringify(shop)};

        const startButton =
          document.getElementById("start");

        startButton.onclick =
          async function () {

            startButton.disabled = true;

            const response =
              await fetch("/translate-all", {
                method: "POST",

                headers: {
                  "Content-Type": "application/json"
                },

                body: JSON.stringify({ shop })
              });

            const data =
              await response.json();

            if (!response.ok) {
              alert(
                data.error ||
                "Starten mislukt."
              );

              startButton.disabled = false;
              return;
            }

            alert(
              "De vertaaljob is gestart."
            );
          };

        async function refreshStatus() {

          try {

            const response =
              await fetch(
                "/translate-status?shop=" +
                encodeURIComponent(shop)
              );

            const data =
              await response.json();

            document.getElementById("status")
              .innerHTML =

              "<strong>Status:</strong> " +
              (data.running
                ? "BEZIG"
                : "KLAAR") +

              "<br>" +

              "Totaal: " +
              data.total +

              "<br>" +

              "Verwerkt: " +
              data.processed +

              "<br>" +

              "Overgeslagen: " +
              data.skipped +

              "<br>" +

              "Fouten: " +
              data.failed +

              "<br>" +

              (data.current
                ? "<br><strong>Huidig:</strong> " +
                  data.current.title
                : "");

            document.getElementById("logs")
              .textContent =
                (data.logs || []).join("\\n");

            if (!data.running) {
              startButton.disabled = false;
            }

          } catch (error) {

            console.error(error);

          }
        }

        refreshStatus();

        setInterval(
          refreshStatus,
          3000
        );

      </script>

    </body>

    </html>
  `);
});

// --------------------------------------------------
// START TRANSLATION
// --------------------------------------------------

app.post("/translate-all", async (req, res) => {
  const shop =
    req.body?.shop;

  if (!validShop(shop)) {
    return res.status(400).json({
      error: "Ongeldige shop."
    });
  }

  const sessionShop =
    getSessionShop(req);

  if (sessionShop !== shop) {
    return res.status(403).json({
      error: "Geen geldige Shopify-sessie."
    });
  }

  if (job.running) {
    return res.status(409).json({
      error: "Er draait al een vertaaljob."
    });
  }

  const connection =
    tokens.get(shop);

  if (!connection) {
    return res.status(401).json({
      error: "Shopify-token ontbreekt. Autoriseer opnieuw."
    });
  }

  if (!OPENAI_API_KEY) {
    return res.status(500).json({
      error: "OPENAI_API_KEY ontbreekt."
    });
  }

  // Meteen antwoorden en de job op de achtergrond uitvoeren.
  runTranslationJob(shop)
    .catch((error) => {
      addLog(
        `Onverwachte job-fout: ${error.message}`
      );
    });

  res.status(202).json({
    ok: true,
    message:
      "De Franse vertaaljob is gestart."
  });
});

// --------------------------------------------------
// STATUS
// --------------------------------------------------

app.get("/translate-status", (req, res) => {
  const shop =
    req.query.shop;

  const sessionShop =
    getSessionShop(req);

  if (
    sessionShop !== shop
  ) {
    return res.status(403).json({
      error: "Geen geldige sessie."
    });
  }

  res.json({
    running: job.running,
    shop: job.shop,
    total: job.total,
    processed: job.processed,
    skipped: job.skipped,
    failed: job.failed,
    current: job.current,
    startedAt: job.startedAt,
    finishedAt: job.finishedAt,
    errors: job.errors.slice(-30),
    logs: job.logs.slice(-50)
  });
});

// --------------------------------------------------
// SERVER
// --------------------------------------------------

if (typeof fetch !== "function") {
  throw new Error(
    "Deze server vereist Node.js 18 of nieuwer."
  );
}

app.listen(PORT, () => {
  console.log(
    `Maison Lévara Shopify API running on port ${PORT}`
  );
});
