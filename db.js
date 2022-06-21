const mongoose = require('mongoose');
require("dotenv").config();
const crypto = require('crypto');
//const nodemailer = require("nodemailer");

const db = mongoose.createConnection(process.env.MONGODB_HOST);
const tokendb = mongoose.createConnection(process.env.MONGODB_OAUTH_HOST);
db.on('error', console.error.bind(console, 'connection error:'));
tokendb.on('error', console.error.bind(console, 'connection error:'));
var User
var Token
var Code
var Application
db.once('open', function() {
	const userSchema = new mongoose.Schema({
	username: {type: String, unique : true},
	passwordHash: Buffer,
	email: {type: String, unique : true},
	salt: Buffer
	});
	User = db.model('User', userSchema);
	const codeSchema = new mongoose.Schema({
		code: String,
		userId: String,
		scopes: Array,
		expires: Date,
		redirectUri: String,
		clientId: String
	})
	Code = db.model('Code', codeSchema);
	const applicationSchema = new mongoose.Schema({
		clientId: String,
		clientSecret: String,
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
					faceplate: 0,
					color: "#00A8F3",
					accessories: [
						{
							name: "key",
							x: 0,
							y: 0
						}
					]
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
				cb(null, "expired", null)
				return Token.deleteOne({token:token}, (err) => {
					if (err) console.error(err)
				});
			}
			return cb(null, null, user)
		})
	})
}

function createAccessToken(clientId, user, scopes, cb) {
	let accessToken = crypto.randomBytes(32).toString("hex");
	let token = new Token({
		token: accessToken,
		client_id: clientId,
		scopes: scopes,
		expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7),
		user: user._id
	})
	token.save((err, token) => {
		if (err) return cb(err, null)
		return cb(null, accessToken)
	})
}

function getUser(userId, cb) {
	User.findOne({_id:userId}, (err, user) => {
		if (err) return cb(err, null)
		return cb(null, user)
	})
}

function getApplication(clientId, cb) {
	Application.findOne({clientId:clientId}, (err, app) => {
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

module.exports = {
	login,
	checkEmail,
	checkName,
	createAccount,
	checkAccessToken,
	createAccessToken,
	getUser,
	getApplication,
	getCodeInformation,
	deleteCode,
	createCode
}
