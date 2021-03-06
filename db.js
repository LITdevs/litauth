const mongoose = require('mongoose');
require("dotenv").config();
const crypto = require('crypto');
const nodemailer = require("nodemailer");
const fs = require("fs")

const db = mongoose.createConnection(process.env.MONGODB_HOST);
const tokendb = mongoose.createConnection(process.env.MONGODB_OAUTH_HOST);
const oldvukkyboxdb = mongoose.createConnection(process.env.MONGODB_OLD_VUKKYBOX_HOST);
const vukkyboxdb = mongoose.createConnection(process.env.MONGODB_VUKKYBOX_HOST);
db.on('error', console.error.bind(console, 'connection error:'));
tokendb.on('error', console.error.bind(console, 'connection error:'));
oldvukkyboxdb.on('error', console.error.bind(console, 'connection error:'));
vukkyboxdb.on('error', console.error.bind(console, 'connection error:'));
var User
var Token
var Code
var Application
var Migrate
var OldVBUser
var VBUser
oldvukkyboxdb.once('open', function () {
	const OldVBUserSchema = new mongoose.Schema({
		githubId: String,
		discordId: String,
		googleId: String,
		primaryEmail: String,
		githubEmail: String,
		discordEmail: String,
		googleEmail: String,
		LinkedAccounts: Array,
		username: String,
		balance: {type: Number, default: 1000},
		gallery: Array,
		loginHourly: {type: Date, default: Date.now()},
		loginDaily: {type: Date, default: Date.now()},
		boxesOpened: {type: Number, default: 0},
		codesRedeemed: {type: Number, default: 0},
		uniqueVukkiesGot: {type: Number, default: 0},
		RVNid: String,
		popupAccepted: {type: Boolean, default: true},
		twoFactor: {type: Boolean, default: false},
		twoFactorSecret: String,
		duplicates: Object,
		transactions: Array,
		beta: {type: Boolean, default: false},
		twoFactorClaimed: {type: Boolean, default: false},
		newsPopup: {type: Boolean, default: true},
	})
	OldVBUser = oldvukkyboxdb.model('User', OldVBUserSchema);
})
vukkyboxdb.once('open', function () {
	const VBUserSchema = new mongoose.Schema({
		litauthId: String,
		primaryEmail: String,
		username: String,
		balance: {type: Number, default: 1000},
		gallery: Array,
		loginHourly: {type: Date, default: Date.now()},
		loginDaily: {type: Date, default: Date.now()},
		boxesOpened: {type: Number, default: 0},
		codesRedeemed: {type: Number, default: 0},
		uniqueVukkiesGot: {type: Number, default: 0},
		popupAccepted: {type: Boolean, default: true},
		twoFactor: {type: Boolean, default: false},
		twoFactorSecret: String,
		duplicates: Object,
		transactions: Array,
		beta: {type: Boolean, default: false},
		twoFactorClaimed: {type: Boolean, default: false},
		newsPopup: {type: Boolean, default: true},
		legacy: Boolean
	})
	VBUser = vukkyboxdb.model('User', VBUserSchema);
})
db.once('open', function() {
	const userSchema = new mongoose.Schema({
		username: {type: String, unique : true},
		passwordHash: Buffer,
		email: {type: String, unique : true},
		avatar: Object,
		salt: Buffer
	});
	User = db.model('User', userSchema);
	const migrateSchema = new mongoose.Schema({
		vukkyboxId: String,
		migrationCode: String
	});
	Migrate = db.model('Migration', migrateSchema);
	const codeSchema = new mongoose.Schema({
		code: {type: String, unique : true},
		userId: String,
		scopes: Array,
		expires: Date,
		redirectUri: String,
		clientId: String
	})
	Code = db.model('Code', codeSchema);
	const applicationSchema = new mongoose.Schema({
		clientId: {type: String, unique : true},
		clientSecret: {type: String, unique : true},
		ownedBy: String,
		scopesAllowed: Array,
		redirectUris: Array,
		name: String,
		description: String
	});
	Application = db.model('Application', applicationSchema);
});

tokendb.once('open', function() {
	const tokenSchema = new mongoose.Schema({
		token: {type: String, unique: true},
		refresh_token: {type: String, unique: true},
		user: String,
		client_id: String,
		scopes: Array,
		expires: Date
	})
	Token = tokendb.model('Token', tokenSchema);
})

function login(email, callback) {
	User.findOne({email: email.toLowerCase()}, function (err, user) {
			if (err) return (callback(err, null));
			callback(null, user);
	});
}

function createAccount(email, username, password, salt, cb) {
	let user = new User({
				email: email,
				username:username,
				passwordHash:password,
				salt:salt,
				avatar: {
					background: "#ffffff",
					color: "#00A8F3",
				}
	})
	user.save(function (err, user) {
		if (err) {
			cb({error: err, success: null})
			return console.error(err);
		}
		return cb({error: null, success: true})
	});
}

function checkEmail(email, cb) {
	User.findOne({email:email}, (err, res) => {
		if (err) {
			cb(true)
			return console.error(err);
		}
		if(res) return cb("used")
		cb(null)
	})
}

function checkName(username, cb) {
	User.findOne({ 'username': { $regex: new RegExp(`^${username}$`), $options: 'i' } }, (err, res) => {
		if (err) {
			cb(true)
			return console.error(err);
		}
		if(res) return cb("used")
		cb(null)
	})
}

function checkAccessToken(token, requestedScopes, cb) { //cb error, state, user
	Token.findOne({token:token}, (err, tokenDoc) => {
		if (err) return cb(err, null, null)
		if(!tokenDoc) return cb(null, "invalid", null)
		User.findOne({_id: tokenDoc.user}, (err, user) => {
			if (err) return cb(err, null, null)
			if(!user) return cb(null, "invalid", null)
			let scopesAllowed = true
			for(let i = 0; i < requestedScopes.length; i++) {
				if(!tokenDoc.scopes.includes(requestedScopes[i])) {
					scopesAllowed = false
					break
				}
			}
			if (!scopesAllowed) return cb(null, "disallowed", null)
			if(tokenDoc.expires < new Date()) {
				return cb(null, "expired", null)
			}
			return cb(null, null, user)
		})
	})
}

function createAccessToken(clientId, user, scopes, cb) {
	let accessToken = crypto.randomBytes(32).toString("hex");
	let token = new Token({
		token: accessToken,
		refresh_token: crypto.randomBytes(32).toString("hex"),
		client_id: clientId,
		scopes: scopes,
		expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7),
		user: user._id
	})
	token.save((err, token) => {
		if (err) return cb(err, null)
		return cb(null, token)
	})
}

function getUser(userId, cb) {
	User.findOne({_id:userId}, (err, user) => {
		if (err) return cb(err, null)
		return cb(null, user)
	})
}

function getToken(tokenId, cb) {
	Token.findOne({_id:tokenId}, (err, token) => {
		if (err) return cb(err, null)
		return cb(null, token)
	})
}

function deleteToken(tokenId, cb) {
	Token.deleteOne({_id:tokenId}, (err) => {
		if (err) {
			console.error(err)
			return cb(err)
		}
		return cb(null)
	})
}


function getApplication(clientId, cb) {
	Application.findOne({clientId:clientId}, (err, app) => {
		if (err) return cb(err, null)
		return cb(null, app)
	})
}

function getApplicationById(id, cb) {
	Application.findOne({_id:id}, (err, app) => {
		if (err) return cb(err, null)
		return cb(null, app)
	})
}

function getCodeInformation(code, cb) {
	Code.findOne({code:code}, (err, code) => {
		if (err) return cb(err, null)
		return cb(null, code)
	})
}

function deleteCode(id) {
	Code.deleteOne({_id:id}, (err) => {
		if (err) console.error(err)
	});
}

function createCode(clientId, userId, scopes, redirectUri, cb) {
	let code = new Code({
		code: crypto.randomBytes(16).toString("hex"),
		userId: userId,
		scopes: scopes,
		expires: new Date(Date.now() + 10 * 60 * 1000),
		redirectUri: redirectUri,
		clientId: clientId 
	})
	code.save((err, savedCode) => {
		if (err) return cb(err, null);
		return cb (null, savedCode);
	})
}

function getUserApplications(userId, cb) {
	Application.find({ownedBy:userId}, (err, apps) => {
		if (err) return cb(err, null)
		return cb(null, apps)
	})
}

function createApplication(userId, cb) {
	let app = new Application({
		clientId: crypto.randomBytes(16).toString("hex"),
		clientSecret: Buffer.from(crypto.randomBytes(32).toString("hex")).toString("base64"),
		ownedBy: userId,
		scopesAllowed: ["identify", "email"],
		redirectUris: [""],
		name: "My Awesome App",
		description: "This app is totally LIT!!"
	})
	app.save((err, app) => {
		if (err) return cb(err, null)
		return cb(null, app)
	})
}

function invalidateTokens(clientId) {
	Token.deleteMany({client_id:clientId}, (err) => {
		if (err) console.error(err)
	});
}

function deleteApplication(id, clientId, cb) {
	Token.deleteMany({client_id:clientId}, (err) => {
		if (err) cb(err);
	});
	Application.deleteOne({_id:id}, (err) => {
		return cb(err)
	})
}

function userAuthorizedApps(userId, cb) {
	let apps = []
	Token.find({user:userId}, (err, tokens) => {
		if (tokens.length == 0) return cb(null, apps)
		let removedTokens = 0
		tokens.forEach((token, index) => {
			/*if (token.expires < new Date()) {
				Token.deleteOne({token:token.token}, (err) => {
					if (err) console.error(err)
				})
				removedTokens++
				if (removedTokens == tokens.length) return cb(null, [])
			}*/
			Application.findOne({clientId:token.client_id}, (err, app) => {
				app.expires = token.expires
				app.scopes = token.scopes
				app.unauthid = token._id
				apps.push(app);
				if (apps.length == tokens.length - removedTokens) cb(null, apps)
			})
		})
	})
}

function findExistingToken(clientId, userId, scopes, callback) {
	// Before creating a new token, we should look for an identical existing authorization to prevent duplication
	Token.findOne({client_id: clientId, user: userId, scopes: scopes}, (err, token) => {
		if (err) return callback(err, null);
		if(!token) return callback(null, null); // return nothing if there is no token
		callback(null, token)
	})
}

function tokenFromRefresh(rt, callback) {
	Token.findOne({refresh_token: rt}, (err, token) => {
		if (err) return callback(err, null);
		callback(null, token)
	})
}

function migrate(migrationCode, lituser, callback) {
	Migrate.findOne({migrationCode: migrationCode}, (err, doc) => {
		if (err) return callback(err, null);
		if (!doc) return callback("invalid", null);
		VBUser.findOne({litauthId: lituser._id}, (err, lvbuser) => {
			if (err) return callback(err, null);
			if (lvbuser) return callback("exists", null);
			OldVBUser.findOne({_id: doc.vukkyboxId}, (err, vbuser) => {
				if (err) return callback(err, null);
				if (!vbuser) return callback("invalid", null);
				let user = new VBUser({
					litauthId: lituser._id,
					primaryEmail: lituser.email,
					username: lituser.username,
					balance: vbuser.balance,
					gallery: vbuser.gallery,
					loginHourly: vbuser.loginHourly,
					loginDaily: vbuser.loginDaily,
					boxesOpened: vbuser.boxesOpened,
					codesRedeemed: vbuser.codesRedeemed,
					uniqueVukkiesGot: vbuser.uniqueVukkiesGot,
					popupAccepted: false,
					twoFactor: vbuser.twoFactor,
					twoFactorSecret: vbuser.twoFactorSecret,
					duplicates: vbuser.duplicates,
					transactions: vbuser.transactions,
					beta: vbuser.beta,
					twoFactorClaimed: vbuser.twoFactorClaimed,
					newsPopup: vbuser.newsPopup,
					legacy: true
				})
				user.save((err, savedUser) => {
					if (err) return callback(err, null);
					doc.remove((err) => {
						if (err) return callback(err, null);
						vbuser.remove((err) => {
							if (err) return callback(err, null);
							callback(null, savedUser)
						})
					})
				})
			})	
		})
	})
}

function sendMigration(email, username, id) {
	let emailConfig = JSON.parse(fs.readFileSync(`${__dirname}/emailConfig.json`).toString())
	let migrationCode = crypto.randomBytes(16).toString("hex")
	let migrate = new Migrate({
		migrationCode: migrationCode,
		vukkyboxId: id
	})
	migrate.save((err, doc) => {
		if (err) console.error(err)
		let transporter = nodemailer.createTransport(emailConfig.mailerConfig);
		let emailContent = fs.readFileSync(`${__dirname}/email/migrate.html`).toString();
		emailContent = emailContent.replace("$username", username);
		emailContent = emailContent.replace("$migrationCode", migrationCode);
		transporter.sendMail({
			from: emailConfig.sender,
			to: email,
			subject: "Important update regarding Vukkybox login",
			html: emailContent
		})
	})
}

function sendMigrationToAll() {
	let emailConfig = JSON.parse(fs.readFileSync(`${__dirname}/emailConfig.json`).toString())
	
	let transporter = nodemailer.createTransport({...emailConfig.mailerConfig, pool: true, maxMessages: Infinity});
	let emailContent = fs.readFileSync(`${__dirname}/email/migrate.html`).toString();

	OldVBUser.find({}, (err, users) => {
		if (err) return console.error(err)
		users.forEach((user, index) => {
			let parsedEmailContent = emailContent.replace("$username", user.username);
			let migrationCode = crypto.randomBytes(10).toString("hex")
			parsedEmailContent = parsedEmailContent.replace("$migrationCode", migrationCode);
			let migrate = new Migrate({
				migrationCode: migrationCode,
				vukkyboxId: user._id
			})
			migrate.save((err, doc) => {
				if (err) console.error(err)
				transporter.sendMail({
					from: emailConfig.sender,
					to: user.primaryEmail,
					subject: "Important update regarding Vukkybox login",
					html: parsedEmailContent
				})
			});
		})
	})
}

module.exports = {
	login,
	checkEmail,
	checkName,
	createAccount,
	checkAccessToken,
	createAccessToken,
	getUser,
	getApplication,
	getApplicationById,
	getCodeInformation,
	deleteCode,
	createCode,
	getUserApplications,
	createApplication,
	invalidateTokens,
	deleteApplication,
	userAuthorizedApps,
	getToken,
	deleteToken,
	findExistingToken,
	tokenFromRefresh,
	migrate,
	sendMigration,
	sendMigrationToAll
}
