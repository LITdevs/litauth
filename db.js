const mongoose = require('mongoose');
require("dotenv").config();
mongoose.connect(process.env.MONGODB_HOST);
//const nodemailer = require("nodemailer");

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
var User
var Code
db.once('open', function() {
	const userSchema = new mongoose.Schema({
	username: {type: String, unique : true},
	passwordHash: Buffer,
	email: {type: String, unique : true},
	salt: Buffer
	});
	User = mongoose.model('User', userSchema);
});
/*let transporter = nodemailer.createTransport({
		host: "smtp.zoho.eu",
		port: 465,
		secure: true,
		auth: {
			user: "vukkybox@litdevs.org",
			pass: process.env.EMAIL_PASS,
		},
	});

async function sendEmail(user, emailContent, emailSubject) {
	let parsedEmailContent = emailContent.replaceAll("$username", user.username)
	if(user.emailCode) parsedEmailContent = parsedEmailContent.replaceAll("$emailRecoveryCode", user.emailCode)
	let info = await transporter.sendMail({
		from: '"Vukkybox" <vukkybox@litdevs.org>',
		to: user.primaryEmail,
		subject: emailSubject,
		html: parsedEmailContent
		});
}
*/

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
				salt:salt
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
	User.findOne({username:username}, (err, res) => {
		if (err) {
			cb(true)
			return console.error(err);
		}
		if(res) return cb("used")
		cb(null)
	})
}

module.exports = {
	login,
	checkEmail,
	checkName,
	createAccount
}
