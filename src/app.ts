import express from "express";
import { User, logedUsers, registeredUsers } from "./database";
import bodyParser from "body-parser";
import { v4 as uuidv4 } from "uuid";
import bcrypt from "bcryptjs";
import { authenticator } from "otplib";
import qrcode from "qrcode";
import u2f from "u2f";
const app = express();
const port = 3000;
const service = "bezpieczenstwo_systemow";
const u2fAppId = "https://localhost:3000";
const u2fFacets = [u2fAppId];

// body-parser
app.use(bodyParser.json()); // dla zapytań z Content-Type: application/json
app.use(bodyParser.urlencoded({ extended: true })); // dla zapytań z Content-Type: application/x-www-form-urlencoded

app.get("/", (req, res) => {
	res.send("Hello World!");
});

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
			const hashedPassword = bcrypt.hashSync(
				password,
				bcrypt.genSaltSync(10)
			);

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
				logedUsers.set(userId, user);
				res.status(200).send(userId);
			} else {
				res.status(400).send("Password is incorrect");
			}
		}
	}
});

//endpoint for logout
app.post("/api/logout", (req, res) => {
	const { userId } = req.body;
	if (!userId) {
		res.status(400).send("User ID is required");
	} else {
		logedUsers.delete(userId);
		res.status(200).send(true);
	}
});

// Wygeneruj kod QR z sekretem, który można zeskanować w aplikacji Google Authenticator
app.get("/register2FA", (req, res) => {
	const { userId } = req.body;
	if (!userId) {
		res.status(400).send("User ID is required");
	} else {
		const user = logedUsers.get(userId);
		if (!user) {
			res.status(400).send("User not found");
		} else {
			const secret = authenticator.generateSecret();
			user.secret = secret;

			const otpauth = authenticator.keyuri(user.email, service, secret);

			qrcode.toDataURL(otpauth, (err, imageUrl) => {
				if (err) {
					console.log("Error with QR");
					return;
				}

				res.status(200).send(imageUrl);
			});
		}
	}
});

// Weryfikacja kodu jednorazowego
app.post("/verifyToken", express.json(), (req, res) => {
	const { userId, token } = req.body;
	if (!userId) {
		res.status(400).send("User ID is required");
	} else {
		const user = logedUsers.get(userId);
		if (!user) {
			res.status(400).send("User not found");
		} else {
			const isVerified = authenticator.verify({
				token,
				secret: user.secret,
			});
			if (isVerified) {
				res.status(200).send(true);
			} else {
				res.status(400).send(false);
			}
		}
	}
});

// registration U2F key
app.post("/registerU2F", express.json(), (req, res) => {
	const { userId, keyHandle, publicKey } = req.body;
	if (!userId) {
		res.status(400).send("User ID is required");
	} else {
		const user = logedUsers.get(userId);
		if (!user) {
			res.status(400).send("User not found");
		} else {
			const registrationRequest = u2f.request(u2fAppId, u2fFacets);
			user.registrationRequest = registrationRequest;

			res.json(registrationRequest);
		}
	}
});

// verify U2F registration
// app.post("/verifyU2F", (req, res) => {
// 	const { userId, keyHandle, signatureData } = req.body;
// 	if (!userId) {
// 		res.status(400).send("User ID is required");
// 	} else {
// 		const user = logedUsers.get(userId);
// 		if (!user) {
// 			res.status(400).send("User not found");
// 		} else {
// 			const registrationRequest = user.registrationRequest;
// 			if (!registrationRequest) {
// 				res.status(400).send("Registration request not found");
// 			} else {
// 				const registrationResponse = u2f.checkRegistration(
// 					registrationRequest,
// 					signatureData,
// 					u2fFacets
// 				);
// 				if (registrationResponse.errorCode) {
// 					res.status(400).send(registrationResponse.errorCode);
// 				} else {
// 					const {
// 						keyHandle: responseKeyHandle,
// 						publicKey: responsePublicKey,
// 					} = registrationResponse;
// 					if (
// 						responseKeyHandle !== keyHandle ||
// 						responsePublicKey !== publicKey
// 					) {
// 						res.status(400).send("Registration failed");
// 					} else {
// 						const {
// 							keyHandle: storedKeyHandle,
// 							publicKey: storedPublicKey,
// 						} = user.u2fKey;
// 						if (storedKeyHandle && storedPublicKey) {
// 							res.status(400).send("User already has a U2F key");
// 						} else {
// 							user.u2fKey = {
// 								keyHandle: responseKeyHandle,
// 								publicKey: responsePublicKey,
// 							};
// 							res.json({
// 								success: true,
// 							});
// 						}
// 					}
// 				}
// 			}
// 		}
// 	}
// });

app.listen(port, () => {
	return console.log(`Express is listening at http://localhost:${port}`);
});
