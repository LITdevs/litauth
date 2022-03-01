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
function findOrCreate(service, profile, callback) {
	switch (service) {
		case "google":
			User.countDocuments({googleId:profile.id},function(err, res){
				if (res) {
					return User.find({googleId:profile.id}, function(err, user) {
						if(!err) callback(user)
						if(err) console.log(err)
					})
				} else {
					let user = new User({
						googleId:profile.id,
						googleEmail:profile.emails[0].value,
						primaryEmail:profile.emails[0].value,
						LinkedAccounts: ["google"],
						username:profile.emails[0].value,
					})
					user.save(function (err, user) {
						if (err) return console.error(err);
						callback(user)
					  });
				}
			})
		break;
		case "github":
			User.countDocuments({githubId:profile.id},function(err, res){
				if (res) {
					return User.find({githubId:profile.id}, function(err, user) {
						if(!err) callback(user)
						if(err) console.log(err)
					})
				} else {
					let user = new User({
						githubId:profile.id,
						githubEmail:profile.email,
						primaryEmail:profile.email,
						LinkedAccounts: ["github"],
						username:profile.username
					})
					user.save(function (err, user) {
						if (err) return console.error(err);
						callback(user)
					  });
				}
			})
		break;
		case "discord":
			User.countDocuments({discordId:profile.id},function(err, res){
				if (res) {
					User.findOne({discordId:profile.id}, function (err, doc) {
						if(err) throw err;
						doc.VCP = profile.VCP;
						doc.save().then(savedDoc => {
							return callback(savedDoc)
						  });
					})
				} else {
					let user = new User({
						discordId:profile.id,
						discordEmail:profile.email,
						primaryEmail:profile.email,
						LinkedAccounts: ["discord"],
						username:profile.username
					})
					user.save(function (err, user) {
						if (err) return console.error(err);
						callback(user)
					  });
				}
			})
	}
}

function changeUsername(user, newUsername) {
	if (user._id) {
	User.findById({_id: user._id}, function (err, doc) {
		if(err) throw err;
		doc.username = newUsername
		doc.save()
	})
} else {
	User.findById({_id: user[0]._id}, function (err, doc) {
		if(err) throw err;
		doc.username = newUsername
		doc.save()
	})
}
}

function getKeyByValue(object, value) {
	return Object.keys(object).find(key => object[key] === value);
  }

function getUser(userId, callback) {
	User.findById({_id: userId}, function (err, doc) {
		if(err) {
			callback(null, err)
			console.log(err)
		};
		if(!doc.RVNid) doc.RVNid = doc._id.toString().substr(8); doc.save();
		callback(doc, null)
	})
}

function deleteUser(profile, callback) {
	User.deleteOne({_id:profile._id}, function(err, res) {
		if(err) {
			callback(500)
			return console.error(err);
		}
		callback("deleted")
	})
}

function listEmails() {
	let commaSeperatedEmails = "";
	let fs = require("fs")
	User.find({}, (err, users) => {
	users.map(user => {
		commaSeperatedEmails += `${user.primaryEmail}, `
	})
	fs.writeFile("./emails.txt", commaSeperatedEmails, function(err) {
		if(err) return console.log(err);
	});
	})
}

function resetPopup() {
	User.updateMany({}, {$set: {popupAccepted: false}}, function (err, docs) {
		if (err) return console.log(err)
	})
}

function checkPopup(userId, callback) {
	User.findOne({_id: userId}, (err, user) => {
		if (err) console.log(err);
		if (err) return callback(500);
		if(user.popupAccepted) {
			callback(true)
		} else {
			callback(false)
		}
	})
}

function acceptPopup(userId) {
	User.findOne({_id: userId}, (err, user) => {
		if (err) console.log(err);
		if (err) return 500;
		user.popupAccepted = true
		user.save()
	})
}

/*
function enabletwoFactor(userId, secret) {
	let fs = require("fs")
	User.findOne({"_id": userId}, function(err, user) {
		if(err) return console.log(err);
		user.twoFactor = true
		user.twoFactorSecret = secret;
		if (!user.twoFactorClaimed) {
			user.twoFactorClaimed = true;
			user.balance += 2000;
			transactions(user._id, {"type": "twofactor", "amount": "+2000", "balance": user.balance, "timestamp": Date.now()})
		}
		let twoFactorEmail = fs.readFileSync(__dirname + "/public/email/2faenable.html", "utf8");
		sendEmail(user, twoFactorEmail, "Two-Factor Authentication enabled on Vukkybox");
		user.save();
	})
}

function disabletwoFactor(userId) {
	let fs = require("fs")
	User.findOne({"_id": userId}, function(err, user) {
		if(err) return console.log(err);
		user.twoFactor = false
		user.twoFactorSecret = null;
		let twoFactorEmail = fs.readFileSync(__dirname + "/public/email/2fadisable.html", "utf8");
		sendEmail(user, twoFactorEmail, "Two-Factor Authentication disabled on Vukkybox");
		user.save();
	})
}
*/
module.exports = {
	findOrCreate,
	changeUsername,
	getUser,
	deleteUser,
	listEmails,
	resetPopup,
	checkPopup,
	acceptPopup
}
