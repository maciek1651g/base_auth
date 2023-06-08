import express from "express";
import { User, sessions, registeredUsers } from "./database";
import bodyParser from "body-parser";
import { v4 as uuidv4 } from "uuid";
import bcrypt from "bcryptjs";
import { authenticator } from "otplib";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import fs from "fs";
import https from "https";
import qrcode from "qrcode";
import * as path from "path";

const app = express();
const port = 3000;

const rpName = "bezpieczenstwo_systemow";
const rpID = "localhost";
const origin = `https://${rpID}:${port}`;
const originFrontendLocalhost = `https://${rpID}:4200`;

// Konfiguracja opcji certyfikatu SSL
const options = {
  key: fs.readFileSync("certs/code.key"),
  cert: fs.readFileSync("certs/code.crt"),
};

// body-parser
app.use(bodyParser.json()); // dla zapytań z Content-Type: application/json
app.use(bodyParser.urlencoded({ extended: true })); // dla zapytań z Content-Type: application/x-www-form-urlencoded

const checkIfLoggedIn = (req, res, next) => {
  const { userId } = req.body;
  if (!userId) {
    res.status(400).send("User ID is required");
  } else {
    const user = sessions.get(userId);
    if (!user) {
      res.status(401).send("User is not logged in");
    } else {
      next();
    }
  }
};

const publicPath = path.join(__dirname, "/public");
app.use(express.static(publicPath));

// endpoint for registration
app.post("/api/register", (req, res) => {
  const { email, password } = req.body;
  // check if username and password are provided
  if (!email || !password) {
    res.status(400).send("Username and password are required");
  } else {
    // check if username is unique
    if (registeredUsers.find((user) => user.email === email)) {
      res.status(400).send("Username already exists");
    } else {
      const hashedPassword = bcrypt.hashSync(password, bcrypt.genSaltSync(15));

      // create a new user
      const user: User = {
        email,
        password: hashedPassword,
      };

      // add user to database
      registeredUsers.push(user);

      // send response
      res.status(201).send(true);
    }
  }
});

//endpoint for login
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  // check if username and password are provided
  if (!email || !password) {
    res.status(400).send("Username and password are required");
  } else {
    // check if username exists
    const user = registeredUsers.find((user) => user.email === email);
    if (!user) {
      res.status(400).send("Username does not exist");
    } else {
      // check if password is correct
      if (bcrypt.compareSync(password, user.password)) {
        const userId = uuidv4();
        sessions.set(userId, user);
        res.status(200).send(userId);
      } else {
        res.status(400).send("Password is incorrect");
      }
    }
  }
});

//endpoint for logout
app.post("/api/logout", checkIfLoggedIn, (req, res) => {
  const { userId } = req.body;
  sessions.delete(userId);
  res.status(200).send(true);
});

// Wygeneruj kod QR z sekretem, który można zeskanować w aplikacji Google Authenticator
app.post("/api/register2FA", checkIfLoggedIn, (req, res) => {
  const { userId } = req.body;
  const user = sessions.get(userId);

  const secret = authenticator.generateSecret();
  user.secret = secret;

  const otpauth = authenticator.keyuri(user.email, origin, secret);

  qrcode.toDataURL(otpauth, (err, imageData) => {
    if (err) {
      console.log("Error with QR");
      return;
    }

    res.status(200).send({ imageData, secret });
  });
});

// Weryfikacja kodu jednorazowego
app.post("/api/verifyToken", checkIfLoggedIn, (req, res) => {
  const { userId, token } = req.body;

  const user = sessions.get(userId);

  if (!user.secret) {
    return res.status(400).send("Secret not found");
  } else {
    const isVerified = authenticator.verify({
      token,
      secret: user.secret,
    });

    if (isVerified) {
      res.status(200).send(true);
    } else {
      res.status(400).send("Invalid token");
    }
  }
});

// registration U2F key start
app.post("/api/registerU2Fstart", checkIfLoggedIn, (req, res) => {
  const { userId } = req.body;
  const user = sessions.get(userId);

  const regOptions = generateRegistrationOptions({
    rpName,
    rpID,
    userID: userId,
    userName: user.email,
    attestationType: "none",
  });
  user.challenge = regOptions.challenge;

  res.json(regOptions);
});

// registration U2F key end
app.post("/api/registerU2Fend", checkIfLoggedIn, async (req, res) => {
  const { userId, attResp } = req.body;
  const user = sessions.get(userId);
  const expectedChallenge = user.challenge;

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: attResp,
      expectedChallenge,
      expectedOrigin: [origin, originFrontendLocalhost],
      expectedRPID: rpID,
    });
  } catch (error) {
    console.error(error);
    return res.status(400).send({ error: error.message });
  }

  const { registrationInfo } = verification;
  const { credentialPublicKey, credentialID, counter } = registrationInfo;

  user.authenticator = {
    credentialID,
    credentialPublicKey,
    counter,
  };

  return res.status(200).send(registrationInfo);
});

// verify U2F key start
app.post("/api/verifyU2Fstart", checkIfLoggedIn, async (req, res) => {
  const { userId } = req.body;
  const user = sessions.get(userId);

  if (!user.authenticator) {
    return res.status(400).send({ error: "No authenticator registered" });
  } else {
    const regOptions = generateAuthenticationOptions({
      allowCredentials: [
        {
          id: user.authenticator.credentialID,
          type: "public-key",
        },
      ],
      userVerification: "preferred",
    });

    user.challenge = regOptions.challenge;

    res.json(regOptions);
  }
});

// verify U2F key end
app.post("/api/verifyU2Fend", checkIfLoggedIn, async (req, res) => {
  const { userId, authResp } = req.body;
  const user = sessions.get(userId);
  const expectedChallenge = user.challenge;

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: authResp,
      expectedChallenge,
      expectedOrigin: [origin, originFrontendLocalhost],
      expectedRPID: rpID,
      authenticator: user.authenticator,
    });
  } catch (error) {
    console.error(error);
    return res.status(400).send({ error: error.message });
  }

  const { authenticationInfo } = verification;
  const { newCounter } = authenticationInfo;

  user.authenticator.counter = newCounter;

  return res.status(200).send(authenticationInfo);
});

https.createServer(options, app).listen(port, () => {
  return console.log(`Express is listening at https://localhost:${port}`);
});
