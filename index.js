import express from "express";
import bodyParser from "body-parser";
import cors from "cors";

const app = express();
app.use(cors());
app.use(bodyParser.json());

// POST /sign endpoint
app.post("/sign", (req, res) => {
  const { access_token, region, method, url } = req.body;

  if (!access_token || !region || !method || !url) {
    return res.status(400).json({ error: "Missing required parameters" });
  }

  // Placeholder logic: later we can add AWS SigV4 signing here
  res.json({
    message: "Received successfully",
    access_token,
    region,
    method,
    url,
  });
});

// Root endpoint (avoid “Cannot GET /” error)
app.get("/", (req, res) => {
  res.send("Amazon SP-API signer is running 🚀");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
