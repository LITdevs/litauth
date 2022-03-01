var express  = require('express')
  , session  = require('express-session')
  , passport = require('passport')
  , DiscordStrategy = require('passport-discord').Strategy
  , app      = express();
const crypto = require("crypto");
require("dotenv").config();
var cookieParser = require('cookie-parser')
const csrf = require("csurf")
const MongoDBStore = require("connect-mongodb-session")(session);
var store = new MongoDBStore({
	uri: process.env.MONGODB_HOST,
	collection: 'sessions',
	clear_interval: 3600
});
var GitHubStrategy = require('passport-github').Strategy;
var GoogleStrategy = require('passport-google-oauth20').Strategy;
var db = require('./db')
passport.serializeUser(function(user, done) {
  done(null, user);
});
passport.deserializeUser(function(obj, done) {
  done(null, obj);
});

var scopes = ['identify', 'email'];
var prompt = 'consent'
app.set("view egine", "ejs")
passport.use(new DiscordStrategy({
	clientID: process.env.CLIENT_ID,
	clientSecret: process.env.CLIENT_SECRET,
	callbackURL: 'https://auth.litdevs.org/callbackdiscord',
	scope: scopes,
	prompt: prompt
}, function(accessToken, refreshToken, profile, done) {
  db.findOrCreate(profile.provider, profile, function(user) {
		done(null, user)
	  })
  
}));
passport.use(new GitHubStrategy({
	clientID: process.env.GITHUB_CLIENT_ID,
	clientSecret: process.env.GITHUB_CLIENT_SECRET,
	callbackURL: "https://auth.litdevs.org/callbackgithub",
	scope: ["user:email"]
  },
  function(accessToken, refreshToken, profile, cb) {
	fetch("https://api.github.com/user/emails", {
						headers: {
			  Accept: "application/json",
							Authorization: `token ${accessToken}`,
						},
		}).then(res => res.json()).then(res => {
	  let filtered = res.reduce((a, o) => (o.primary && a.push(o.email), a), [])      
	  profile.email = filtered[0]
	}).then (h => {
	  db.findOrCreate(profile.provider, profile, function(user) {
		cb(null, user)
	  })
	})
	
  }
));
passport.use(new GoogleStrategy({
	clientID: process.env.GOOGLE_CLIENT_ID,
	clientSecret: process.env.GOOGLE_CLIENT_SECRET,
	callbackURL: "https://auth.litdevs.org/callbackgoogle",
	scope: ["profile", "email"]
  },
  function(token, tokenSecret, profile, cb) {
	db.findOrCreate(profile.provider, profile, function(user) {
	  cb(null, user)
	})
  }
));
app.use(session({
	secret: process.env.SESSION_SECRET,
	resave: true,
	saveUninitialized: true,
	store: store
}));
app.use(passport.initialize());
app.use(passport.session());
app.use("/resources", express.static('public/resources'))
app.use(express.urlencoded({extended:true}));
app.use(express.json())
app.use(cookieParser())
app.use(csrf({cookie: true, sessionKey: process.env.SESSION_SECRET}))
app.use(function (err, req, res, next) {
	if (err.code !== 'EBADCSRFTOKEN') return next(err)
	let csrfWhitelist = []
	if(!csrfWhitelist.includes(req.url)) return res.send("Couldn't verify Cross Site Request Forgery prevention")
	if(csrfWhitelist.includes(req.url)) return next()
})
app.set('trust proxy', 1);

/*function popupMid(req, res, next) {
	if (/MSIE|Trident/.test(req.headers['user-agent'])) return res.render(`${__dirname}/public/error.ejs`, { stacktrace: null, friendlyError: "Your browser is no longer supported by Vukkybox. Please <a href='https://browser-update.org/update-browser.html'>update your browser</a>." });
	if (req.headers['user-agent'].indexOf('Safari') != -1 && req.headers['user-agent'].indexOf('Macintosh') == -1 && req.headers['user-agent'].indexOf('OPR') == -1 && req.headers['user-agent'].indexOf('Edge') == -1 && req.headers['user-agent'].indexOf('Chrome') == -1) return res.render(`${__dirname}/public/error.ejs`, { stacktrace: null, friendlyError: "Sorry, but iPhones and iPads are not currently supported by Vukkybox, because Safari is terrible, and all web browsers there are Safari in a trench coat.<br>Please buy a good device, such as an Android phone, or even better... a computer!<br><br><img src='https://dokodemo.neocities.org/images/buttons/phonechump.gif'>" });
	if (!req.isAuthenticated()) {
		return next()
	}
	let user = req.user._id ? req.user : req.user[0]
	db.checkPopup(user._id, function (accepted) {
		if (accepted == 500) return res.send("500: Internal Server Error");
		if (!accepted) {
			return res.redirect("/popup")
		} else {
			db.checkNews(user._id, accepted => {
				if (!accepted) req.session.news = true;
				if (accepted) req.session.news = false;
				req.session.save();
				return next()
			})
		}
	})
}*/

app.get('/login', function(req, res) {
	let user = req.isAuthenticated() ? req.user._id ? req.user : req.user[0] : null
	res.render(__dirname + '/public/login.ejs', {user: user, gravatarHash: user ? crypto.createHash("md5").update(user.primaryEmail.toLowerCase()).digest("hex") : null, redirect: req.session.redirectTo != undefined && req.session.redirectTo.length > 1 ? true : false});
});

app.get("/profile", checkAuth, popupMid, function (req, res) {
	let user = req.isAuthenticated() ? req.user._id ? req.user : req.user[0] : null
	res.render(__dirname + '/public/profile.ejs', {user: user, gravatarHash: user ? crypto.createHash("md5").update(user.primaryEmail.toLowerCase()).digest("hex") : null});
});

app.get("/editProfile", checkAuth, popupMid, function (req, res) { 
	let user = req.isAuthenticated() ? req.user._id ? req.user : req.user[0] : null
	res.render(__dirname + '/public/editProfile.ejs', {user: user, gravatarHash: user ? crypto.createHash("md5").update(user.primaryEmail.toLowerCase()).digest("hex") : null, csrfToken: req.csrfToken()});
})

app.post("/editProfile", checkAuth, function(req, res) {
	if(req.body.username != "") {
	  db.changeUsername(req.user, req.body.username)
	  req.session.passport.user.username = req.body.username
	}
	res.redirect("/profile")
})

app.get('/privacy', function(req, res){
	res.redirect('/resources/privacy.html');
});

app.get('/terms', function(req, res){
	res.redirect('/resources/terms.html');
});

app.get('/delete', checkAuth, function(req,res) {
	user = req.user._id ? req.user : req.user[0]
	res.render(__dirname + "/public/deleteConfirm.ejs", {csrfToken: req.csrfToken(), twoFactor: user.twoFactor})
})
/*
app.post('/delete2fa', checkAuth, function(req, res) {
	user = req.user._id ? req.user : req.user[0]
	if(!twoFactor) res.status(400).send("what are you doing.")
	var verified = speakeasy.totp.verify({ secret: user.twoFactorSecret,
		encoding: 'base32',
		token: req.body.otp });
	if(!verified) {
		req.session.twoFactorValidated = false;
		req.session.delete2fa = false; //lets make sure that it is absolutely for sure not allowed to delete without 2fa
		req.session.save();
		res.send({verified: false})
	}
	if(verified) {
		req.session.delete2fa = true;
		req.session.save();
		res.send({verified: true})
	}
	
	
})
*/
app.post("/delete", checkAuth, function(req, res) {
	user = req.user._id ? req.user : req.user[0]
	if(user.twoFactor && !req.session.delete2fa) res.redirect("/logout");
	db.deleteUser(user, function(result) {
		if(result == 500) {
			res.redirect('/resources/500.html');
		} else {
			req.logout();
			res.redirect('/resources/deleted.html');
		}
	});
})

app.get('/loginDiscord', passport.authenticate('discord', { scope: scopes, prompt: prompt }), function(req, res) {
	req.session.twoFactorValidated = false
	req.session.twoFactorLastValidated = 0
	req.session.save()
});
app.get('/loginGithub', passport.authenticate('github'), function(req, res) {
	req.session.twoFactorValidated = false
	req.session.twoFactorLastValidated = 0
	req.session.save()
});
app.get('/loginGoogle', passport.authenticate('google'), function(req, res) {
	req.session.twoFactorValidated = false
	req.session.twoFactorLastValidated = 0
	req.session.save()
});

app.get('/callbackdiscord',
	passport.authenticate('discord', { failureRedirect: '/' }), function(req, res) { 
		req.session.twoFactorValidated = false
		req.session.twoFactorLastValidated = 0
		req.session.save()
		//if(req.user.twoFactor) return res.redirect('/validate2fa')
		if(req.session.redirectTo) {
			let dest = req.session.redirectTo;
			req.session.redirectTo = "/"
			res.redirect(dest) 
		} else {
			res.redirect('/')
		}
	} // auth success
);

app.get('/callbackgithub',
	passport.authenticate('github', { failureRedirect: '/' }), function(req, res) { 
		req.session.twoFactorValidated = false
		req.session.twoFactorLastValidated = 0
		req.session.save()
		//if(req.user.twoFactor) return res.redirect('/validate2fa')
		if(req.session.redirectTo) {
			let dest = req.session.redirectTo;
			req.session.redirectTo = "/"
			res.redirect(dest) 
		} else {
			res.redirect('/')
		}
	} // auth success
);
app.get('/callbackgoogle',
	passport.authenticate('google', { failureRedirect: '/' }), function(req, res) {
		req.session.twoFactorValidated = false
		req.session.twoFactorLastValidated = 0
		req.session.save()
		//if(req.user.twoFactor) return res.redirect('/validate2fa')
		if(req.session.redirectTo) {
			let dest = req.session.redirectTo;
			req.session.redirectTo = "/"
			res.redirect(dest) 
		} else {
			res.redirect('/')
		}
	} // auth success
);

/*
app.get('/otpcallback', function(req, res) {
	if(!req.isAuthenticated()) return res.redirect('/login')
	if(!req.user.twoFactor) return res.redirect('/2fa')
	if(!req.session.twoFactorValidated) return res.redirect('/validate2fa')
	if(req.session.redirectTo) {
		let dest = req.session.redirectTo;
		req.session.redirectTo = "/"
		res.redirect(dest) 
	} else {
		res.redirect('/')
	}
})
*/

app.get('/logout', function(req, res) {
	req.logout();
	res.redirect('/');
});
/*
app.get("/popup", checkAuth, function (req, res) {
	let user = req.isAuthenticated() ? req.user._id ? req.user : req.user[0] : null
	res.render(__dirname + '/public/popup.ejs', {csrfToken: req.csrfToken(), user: user, gravatarHash: crypto.createHash("md5").update(user.primaryEmail.toLowerCase()).digest("hex"), redirect: req.session.redirectTo != undefined && req.session.redirectTo.length > 1 ? true : false});
	
})

app.post('/popup', checkAuth, function (req, res) {
	if(req.body.popup != "yes") return res.redirect("/delete")
	let user = req.isAuthenticated() ? req.user._id ? req.user : req.user[0] : null
	db.acceptPopup(user._id)
	res.redirect("/")
})*/

function checkAuth(req, res, next) {
	let user = req.isAuthenticated() ? req.user._id ? req.user : req.user[0] : null
	if(user) {
		//if (user.twoFactor && !req.session.twoFactorValidated) return res.redirect("/validate2fa")
		db.lastLogin(user, function(newBalance, newUser) {
			req.session.passport.user = newUser
			req.session.passport.user.balance = newBalance
			req.session.save()
		})
		return next();
	}
	req.session.redirectTo = req.path;
	res.redirect(`/login`)
}

/*function checkAuthnofa(req, res, next) {
	let user = req.isAuthenticated() ? req.user._id ? req.user : req.user[0] : null
	if(user) {
		db.lastLogin(user, function(newBalance, newUser) {
			req.session.passport.user = newUser
			req.session.passport.user.balance = newBalance
			req.session.save()
		})
		return next();
	}
	req.session.redirectTo = req.path;
	res.redirect(`/login`)
}

function checkAuthtime(req, res, next) {
	let user = req.isAuthenticated() ? req.user._id ? req.user : req.user[0] : null
	if(!user) return res.redirect("/login")
	if(user) {
		db.lastLogin(user, function(newBalance, newUser) {
			req.session.passport.user = newUser
			req.session.passport.user.balance = newBalance
			req.session.save()
		})
		if(!user.twoFactor) return next();
		if(!req.session.twoFactorValidated) return res.redirect("/validate2fa")
		let diffMs = Date.now() - req.session.twoFactorLastValidated;

		if (diffMs > 1800000) return res.redirect("/validate2fa")
		return next();
	}
	res.send("what")
}
app.get('/2fa', checkAuthnofa, function(req, res) {
	let user = req.user._id ? req.user : req.user[0];
	db.getUser(user._id, user => {
		if(user.twoFactor) return res.render(`${__dirname}/public/2fareset.ejs`, {csrfToken: req.csrfToken(), user: user, gravatarHash: crypto.createHash("md5").update(user.primaryEmail.toLowerCase()).digest("hex")});
		let secret = speakeasy.generateSecret({name: "Vukkybox 2FA"});
		req.session.two_factor_temp_secret = secret.base32;
		req.session.save()
		qrcode.toDataURL(secret.otpauth_url, function(err, dataUrl) {
			if (err) return res.render(__dirname + '/public/error.ejs', {stacktrace: null, friendlyError: "Something went wrong while starting the 2FA flow. <br>For your privacy the stacktrace is hidden, if this happens again please contact us."});
			res.render(`${__dirname}/public/2fa.ejs`, {csrfToken: req.csrfToken(), user: user, qrDataUrl: dataUrl, gravatarHash: crypto.createHash("md5").update(user.primaryEmail.toLowerCase()).digest("hex")});
		});
	})
});

app.get('/validate2fa', function(req, res) {
	if (!req.isAuthenticated) return res.redirect("/login");
	let user = req.user._id ? req.user : req.user[0];
	db.getUser(user._id, user => {
		if(!user.twoFactor) return res.send("you dont even have 2FA enabled lol");
		res.render(`${__dirname}/public/validate2fa.ejs`, {csrfToken: req.csrfToken(), user: user, gravatarHash: crypto.createHash("md5").update(user.primaryEmail.toLowerCase()).digest("hex")});	
	})
});

app.post('/votp', checkAuthnofa, function(req, res) {
	let user = req.user._id ? req.user : req.user[0];
	db.getUser(user._id, user => {
		var verified = speakeasy.totp.verify({ secret: user.twoFactorSecret,
			encoding: 'base32',
			token: req.body.otp });
		if(!verified) {
			req.logout()
			return res.send({valid: false});
		}
		if(verified) {
			res.send({valid: true});
			req.session.twoFactorValidated = true;
			req.session.twoFactorLastValidated = Date.now();
			req.session.save();
		}
	})
})

app.post('/fotp', checkAuth, function(req, res) {
	let user = req.user._id ? req.user : req.user[0];
	if(user.twoFactor) return res.status(403).send("2fa already enabled");
	if(!req.session.two_factor_temp_secret) return res.status(400).send("2fa flow not started");
	let userInput = req.body.otp;
	var verified = speakeasy.totp.verify({ secret: req.session.two_factor_temp_secret,
		encoding: 'base32',
		token: userInput });
	if(!verified) return res.status(400).send({valid: false});
	db.enabletwoFactor(user._id, req.session.two_factor_temp_secret);
	res.send({valid: true});
})


app.post('/emailCode', checkAuthnofa, function(req, res) {
	let user = req.user._id ? req.user : req.user[0];
	let secret = speakeasy.generateSecret({length: 8});
	user.emailCode = secret.base32;
	req.session.emailCode = secret.base32;
	req.session.save()
	db.sendEmail(user, fs.readFileSync(`${__dirname}/public/email/emailCode.html`, "utf8"), "Vukkybox Authenticator recovery code");
})

app.post('/emailCheckCode', checkAuthnofa, function(req, res) {
	let user = req.user._id ? req.user : req.user[0];
	if(!req.session.emailCode) return res.status(400).send({valid: false});
	if(req.body.otp != req.session.emailCode) return res.status(400).send({valid: false});
	db.disabletwoFactor(user._id);
	res.send({valid: true});
})

app.post('/2fareset', checkAuthnofa, function(req, res) {
	let user = req.user._id ? req.user : req.user[0];
	db.getUser(user._id, user => {
		var verified = speakeasy.totp.verify({ secret: user.twoFactorSecret,
			encoding: 'base32',
			token: req.body.otp });
		if(!verified) return res.status(400).render(`${__dirname}/public/2fareset.ejs`, {failure: true, csrfToken: req.csrfToken(), user: user, gravatarHash: crypto.createHash("md5").update(user.primaryEmail.toLowerCase()).digest("hex")});
		if(verified) db.disabletwoFactor(user._id);
		if(verified) res.render(`${__dirname}/public/2fareset.ejs`, {successful: true, csrfToken: req.csrfToken(), user: user, gravatarHash: crypto.createHash("md5").update(user.primaryEmail.toLowerCase()).digest("hex")});
	})
})
*/
app.use(function (err, req, res, next) {
	console.error(err.stack);
	if(err.message == 'Invalid "code" in request.') {
		return res.status(500).render(`${__dirname}/public/error.ejs`, { stacktrace: null, friendlyError: "It looks like we couldn't log you in. Would you mind <a href='/login'>trying that again</a>?" });
	}
	res.status(500).render(`${__dirname}/public/error.ejs`, { stacktrace: err.stack, friendlyError: null });
});

// and now for something completely different
app.get('/.well-known/security.txt', function (req, res) {
    res.type('text/plain');
    res.send("Contact: mailto:contact@litdevs.org");
});

app.get('*', function(req, res){
	res.status(404).render(`${__dirname}/public/404.ejs`);
});

var fs = require('fs');
var http = require('http');

const httpServer = http.createServer(app);

httpServer.listen(81, () => {
	console.log('HTTP Server running on port 81');
});