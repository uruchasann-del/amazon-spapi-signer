import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import crypto from "crypto";

const app = express();
app.use(cors());
app.use(bodyParser.json());

app.get("/", (req, res) => {
  res.send("Amazon SP-API signer is running 🚀");
});

// SIGN route
app.post("/sign", async (req, res) => {
  try {
    const { access_token, region, method, url, body } = req.body;

    const host = new URL(url).host;
    const path = new URL(url).pathname + (new URL(url).search || "");
    const now = new Date().toISOString().replace(/[:-]|\.\d{3}/g, "");
    const amzDate = now.slice(0, 8) + "T" + now.slice(8) + "Z";

    // CHANGE THESE VALUES TO YOUR KEYS
    const AWS_ACCESS_KEY = process.env.AWS_ACCESS_KEY_ID;
    const AWS_SECRET_KEY = process.env.AWS_SECRET_ACCESS_KEY;
    const ROLE_SESSION_NAME = "spapi-signing";

    const service = "execute-api";
    const regionName = region;
    const dateStamp = amzDate.substring(0, 8);
    const canonicalHeaders = `host:${host}\n`;
    const signedHeaders = "host";
    const payloadHash = crypto.createHash("sha256").update(body || "", "utf8").digest("hex");
    const canonicalRequest = `${method}\n${path}\n\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;
    const algorithm = "AWS4-HMAC-SHA256";
    const credentialScope = `${dateStamp}/${regionName}/${service}/aws4_request`;
    const stringToSign = `${algorithm}\n${amzDate}\n${credentialScope}\n${crypto.createHash("sha256").update(canonicalRequest, "utf8").digest("hex")}`;
    const kDate = crypto.createHmac("sha256", "AWS4" + AWS_SECRET_KEY).update(dateStamp).digest();
    const kRegion = crypto.createHmac("sha256", kDate).update(regionName).digest();
    const kService = crypto.createHmac("sha256", kRegion).update(service).digest();
    const kSigning = crypto.createHmac("sha256", kService).update("aws4_request").digest();
    const signature = crypto.createHmac("sha256", kSigning).update(stringToSign).digest("hex");

    const authorizationHeader =
      `${algorithm} Credential=${AWS_ACCESS_KEY}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    const headers = {
      Authorization: authorizationHeader,
      "x-amz-access-token": access_token,
      "x-amz-date": amzDate,
      host,
      "content-type": "application/json"
    };

    res.json({ headers });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));

