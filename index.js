import express from "express";
import aws4 from "aws4";
import bodyParser from "body-parser";

const app = express();
app.use(bodyParser.json());

app.post("/sign", (req, res) => {
  const { method, path, region, host, accessKeyId, secretAccessKey, body } = req.body;

  const options = {
    host,
    path,
    service: "execute-api",
    region,
    method,
    body: body ? JSON.stringify(body) : undefined,
    headers: { "Content-Type": "application/json" }
  };

  aws4.sign(options, {
    accessKeyId,
    secretAccessKey
  });

  res.json({
    headers: options.headers
  });
});

app.listen(3000, () => console.log("SP-API signer running on port 3000"));
