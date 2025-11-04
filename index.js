import express from "express";
import cors from "cors";
import crypto from "crypto";

const app = express();
app.use(cors());
app.use(express.json());

// Function to sign SP-API requests
function sign({ region, url, method }) {
  const accessKey = process.env.AWS_ACCESS_KEY_ID;
  const secretKey = process.env.AWS_SECRET_ACCESS_KEY;
  const service = "execute-api";

  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "") + "Z";
  const dateStamp = amzDate.substring(0, 8);

  const host = new URL(url).host;
  const canonicalUri = new URL(url).pathname;
  const canonicalQuerystring = "";
  const canonicalHeaders = `host:${host}\n`;
  const signedHeaders = "host";
  const payloadHash = crypto.createHash("sha256").update("").digest("hex");
  const canonicalRequest = [
    method,
    canonicalUri,
    canonicalQuerystring,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");

  const algorithm = "AWS4-HMAC-SHA256";
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    algorithm,
    amzDate,
    credentialScope,
    crypto.createHash("sha256").update(canonicalRequest).digest("hex"),
  ].join("\n");

  function signKey(key, msg) {
    return crypto.createHmac("sha256", key).update(msg).digest();
  }

  const kDate = signKey("AWS4" + secretKey, dateStamp);
  const kRegion = signKey(kDate, region);
  const kService = signKey(kRegion, service);
  const kSigning = signKey(kService, "aws4_request");
  const signature = crypto
    .createHmac("sha256", kSigning)
    .update(stringToSign)
    .digest("hex");

  const authorizationHeader = `${algorithm} Credential=${accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  return {
    Authorization: authorizationHeader,
    "x-amz-date": amzDate,
    host,
  };
}

app.post("/sign", (req, res) => {
  try {
    const headers = sign(req.body);
    res.json({ headers });
  } catch (error) {
    res.status(500).send({ error: error.message });
  }
});

app.listen(10000, () => console.log("Amazon SP-API signer running 🚀"));
