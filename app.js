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
function popupMid(req, res, next) {
	next()
	if (/MSIE|Trident/.test(req.headers['user-agent'])) return res.render(`${__dirname}/public/error.ejs`, { stacktrace: null, friendlyError: "Your browser is no longer supported by Vukkybox. Please <a href='https://browser-update.org/update-browser.html'>update your browser</a>." });
	if (req.headers['user-agent'].indexOf('Safari') != -1 && req.headers['user-agent'].indexOf('Macintosh') == -1 && req.headers['user-agent'].indexOf('OPR') == -1 && req.headers['user-agent'].indexOf('Edge') == -1 && req.headers['user-agent'].indexOf('Chrome') == -1) return res.render(`${__dirname}/public/error.ejs`, { stacktrace: null, friendlyError: "Sorry, but iPhones and iPads are not currently supported by Vukkybox, because Safari is terrible, and all web browsers there are Safari in a trench coat.<br>Please buy a good device, such as an Android phone, or even better... a computer!<br><br><img src='https://dokodemo.neocities.org/images/buttons/phonechump.gif'>" });
	if (!req.isAuthenticated()) {
		return next()
	}
	next()
}

app.get('/', function(req, res) {
	let user = req.isAuthenticated() ? req.user._id ? req.user : req.user[0] : null
	res.render(__dirname + '/public/index.ejs', {user: user, gravatarHash: user ? crypto.createHash("md5").update(user.primaryEmail.toLowerCase()).digest("hex") : null, redirect: req.session.redirectTo != undefined && req.session.redirectTo.length > 1 ? true : false});
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
	res.render(__dirname + "/public/deleteConfirm.ejs", {csrfToken: req.csrfToken()})
})

app.post("/delete", checkAuth, function(req, res) {
	user = req.user._id ? req.user : req.user[0]
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
	req.session.save()
});
app.get('/loginGithub', passport.authenticate('github'), function(req, res) {
	req.session.save()
});
app.get('/loginGoogle', passport.authenticate('google'), function(req, res) {
	req.session.save()
});

app.get('/callbackdiscord',
	passport.authenticate('discord', { failureRedirect: '/' }), function(req, res) {
		req.session.save()
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
		req.session.save()
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
		req.session.save()
		if(req.session.redirectTo) {
			let dest = req.session.redirectTo;
			req.session.redirectTo = "/"
			res.redirect(dest) 
		} else {
			res.redirect('/')
		}
	} // auth success
);

app.get('/logout', function(req, res) {
	req.logout();
	res.redirect('/');
});

function checkAuth(req, res, next) {
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
	res.redirect(`/`)
}

app.use(function (err, req, res, next) {
	console.error(err.stack);
	if(err.message == 'Invalid "code" in request.') {
		return res.status(500).render(`${__dirname}/public/error.ejs`, { stacktrace: null, friendlyError: "It looks like we couldn't log you in. Would you mind <a href='/'>trying that again</a>?" });
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

httpServer.listen(87, () => {
	console.log('HTTP Server running on port 87');
});