// Require land
var express  = require('express')
  , session  = require('express-session')
  , passport = require('passport')
  , LocalStrategy = require('passport-local').Strategy
  , app      = express()
  , crypto = require("crypto")
  , cookieParser = require('cookie-parser')
  , flash = require('express-flash')
  , csrf = require("csurf")
  , fs = require('fs')
  , nodemailer = require("nodemailer")
  , rateLimit = require('express-rate-limit');
require("dotenv").config();
const MongoDBStore = require("connect-mongodb-session")(session);

var oobe = require('./routes/oobe');

// Check for email config
let emailConfig = false
if (fs.existsSync(`${__dirname}/emailConfig.json`)) {
	emailConfig = require(`${__dirname}/emailConfig.json`)
}

// random globals land
var store = new MongoDBStore({
	uri: process.env.MONGODB_HOST,
	collection: 'sessions',
	clear_interval: 3600
});
var db = require('./db')

// passport does something
passport.serializeUser(function(user, done) {
  done(null, user);
});
passport.deserializeUser(function(obj, done) {
  done(null, obj);
});

// app.use land
app.use(session({
	secret: process.env.SESSION_SECRET,
	resave: true,
	saveUninitialized: true,
	store: store
}));
app.use(flash());
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
app.use(function (req, res, next) {
	if (/MSIE|Trident/.test(req.headers['user-agent'])) return res.render(`${__dirname}/public/error.ejs`, { stacktrace: null, friendlyError: "Your browser is no longer supported. Please <a href='https://browser-update.org/update-browser.html'>update your browser</a>." });
	if(req.method == "GET" && !emailConfig && req.url != "/oobe/emailFinal" ) return res.render(`${__dirname}/public/emailConfig.ejs`, {csrfToken: req.csrfToken()});
	//if (req.headers['user-agent'].indexOf('Safari') != -1 && req.headers['user-agent'].indexOf('Macintosh') == -1 && req.headers['user-agent'].indexOf('OPR') == -1 && req.headers['user-agent'].indexOf('Edge') == -1 && req.headers['user-agent'].indexOf('Chrome') == -1) return res.render(`${__dirname}/public/error.ejs`, { stacktrace: null, friendlyError: "Sorry, but iPhones and iPads are not currently supported, because Safari is terrible, and all web browsers there are Safari in a trench coat.<br>Please buy a good device, such as an Android phone, or even better... a computer!<br><br><img src='https://dokodemo.neocities.org/images/buttons/phonechump.gif'>" });
	next()
});
app.use(function (err, req, res, next) {
	console.error(err.stack);
	if(err.message == 'Invalid "code" in request.') {
		return res.status(500).render(`${__dirname}/public/error.ejs`, { stacktrace: null, friendlyError: "It looks like we couldn't log you in. Would you mind <a href='/'>trying that again</a>?" });
	} // TODO: make it use flash messages
	res.status(500).render(`${__dirname}/public/error.ejs`, { stacktrace: err.stack, friendlyError: null });
});
app.use("/oobe", oobe);

passport.use(new LocalStrategy(function verify(username, password, cb) {
	db.login(username, function(err, data) {
	  if (err) return cb(err);
	  if (!data) return cb(null, false, { message: 'Incorrect email address.' });
	  crypto.pbkdf2(password, data.salt, 310000, 32, 'sha256', function(err, hashedInput) {
		if (err) { return cb(err); }
		if (!crypto.timingSafeEqual(data.passwordHash, hashedInput)) {
		  return cb(null, false, { message: 'Incorrect password.' });
		}
		return cb(null, data);
	  });
	});
}));

app.set('trust proxy', 1);

// normal page routing

app.get('/', function(req, res) {
	let user = req.isAuthenticated() ? req.user._id ? req.user : req.user[0] : null
	res.render(__dirname + '/public/index.ejs', {user: user, csrfToken: req.csrfToken()});
});

app.get('/privacy', function(req, res){
	res.redirect('/resources/privacy.html');
});

app.get('/terms', function(req, res){
	res.redirect('/resources/terms.html');
});

app.get('/logout', function(req, res) {
	req.logout();
	res.send('you killed niko');
});

/*app.post("/login/register", (req, res) => {
	//TODO: use flash messages
	req.body.email = req.body.email.toLowerCase();
	if(!req.body.email.includes("@") || !req.body.email.includes(".")) return res.status(400).send({type: "email", message: "Invalid email address"});
	if(req.body.username.trim().length < 3) return res.status(400).send({type: "username", message: "Username must be at least 3 characters long"});
	if(req.body.password.trim().length < 8) return res.status(400).send({type: "password", message: "Password must be at least 8 characters long"});
	if(req.body.password !== req.body.password2) return res.status(400).send({type: "password", message: "Passwords do not match"});
	
	db.checkEmail(req.body.email, resp => {
		if (resp) {
			if (resp == "used") return res.status(400).send({type: "email", message: "An account is already registered to this email address"});
			return res.status(500).send({type: "error", message: "Internal server error, please try again later"});
		}

		db.checkName(req.body.username, resp => {
			if (resp) {
				if (resp == "used") return res.status(400).send({type: "username", message: "This username is already taken!"});
				return res.status(500).send({type: "error", message: "Internal server error, please try again later"});
			}

			let salt = crypto.randomBytes(16);
			crypto.pbkdf2(req.body.password, salt, 310000, 32, 'sha256', (err, pwd) => {
				if (err) return res.status(500).send({type: "error", message: "Internal server error, please try again later"});
				db.createAccount(req.body.email, req.body.username, pwd, salt, data => {
					if(data.error) return res.status(500).send({type: "error", message: data.error});
					if(data.success) return res.sendStatus(200)
				});
			});
		})
	})
})*/

let registerRateLimit = rateLimit({
	windowMs: 60 * 1000, // 1 minute
	max: 1, // limit each IP to 1 requests per windowMs
	message: "Too many requests, please try again later",
	keyGenerator: function (req /*, res*/) {
		return req.headers["cf-connecting-ip"];
	},
})

app.post("/login/register/1", (req, res) => {
	//TODO: use flash messages
	req.body.email = req.body.email.toLowerCase();
	if(!req.body.email.includes("@") || !req.body.email.includes(".")) return res.status(400).send({type: "email", message: "Invalid email address"});
	if(req.body.username.trim().length < 3) return res.status(400).send({type: "username", message: "Username must be at least 3 characters long"});
	if(req.body.password.trim().length < 8) return res.status(400).send({type: "password", message: "Password must be at least 8 characters long"});
	if(req.body.password !== req.body.password2) return res.status(400).send({type: "password", message: "Passwords do not match"});
	let usernameRegex = /[^a-zA-Z0-9\-_.,]/
	if(usernameRegex.test(req.body.username)) return res.status(400).send({type: "username", message: "Username must match /[^a-zA-Z0-9\-_.,]/"});
	
	db.checkEmail(req.body.email, resp => {
		if (resp) {
			if (resp == "used") return res.status(400).send({type: "email", message: "An account is already registered to this email address"});
			return res.status(500).send({type: "error", message: "Internal server error, please try again later"});
		}

		db.checkName(req.body.username, resp => {
			if (resp) {
				if (resp == "used") return res.status(400).send({type: "username", message: "This username is already taken!"});
				return res.status(500).send({type: "error", message: "Internal server error, please try again later"});
			}
			registerRateLimit(req, res, () => {
				let salt = crypto.randomBytes(16);
				crypto.pbkdf2(req.body.password, salt, 310000, 32, 'sha256', (err, pwd) => {
					if (err) return res.status(500).send({type: "error", message: "Internal server error, please try again later"});
					req.session.email = req.body.email
					req.session.username = req.body.username
					req.session.passwordHash = pwd
					req.session.salt = salt
					req.session.resend = false
					req.session.emailCode = ~~(Math.random() * 10 ** 6)
					req.session.save(err => {
						if (err) return res.status(500).send({type: "error", message: "Internal server error, please try again later"});
						let transporter = nodemailer.createTransport(emailConfig.mailerConfig);
						let emailContent = fs.readFileSync(`${__dirname}/email/verification.html`).toString();
						emailContent = emailContent.replace("$username", req.body.username);
						emailContent = emailContent.replace("$emailVerificationCode", req.session.emailCode);
						transporter.sendMail({
							from: emailConfig.sender,
							to: req.body.email,
							subject: "LITauth Account Verification",
							html: emailContent
						}).then(info => {
							res.sendStatus(200)
						})
					})
				});
			})
		})
	})
})

app.get("/login/register/resend", (req, res) => {
	if (!req.session.emailCode) return res.status(400).send({type: "error", message: "Registration is not in progress"});
	if (req.session.resend) return res.status(403).send({type: "error", message: "You have already requested a verification email"});
	let transporter = nodemailer.createTransport(emailConfig.mailerConfig);
	let emailContent = fs.readFileSync(`${__dirname}/email/verification.html`).toString();
	emailContent = emailContent.replace("$username", req.session.username);
	emailContent = emailContent.replace("$emailVerificationCode", req.session.emailCode);
	transporter.sendMail({
		from: emailConfig.sender,
		to: req.session.email,
		subject: "LITauth Account Verification",
		html: emailContent
	}).then(info => {
		req.session.resend = true
		req.session.save()
		res.sendStatus(200)
	})
})

app.post('/login/password', passport.authenticate('local', {
	successReturnToOrRedirect: '/info',
	failureRedirect: '/',
	failureFlash: true
}));

app.get('/register', (req, res) => {
	let user = req.isAuthenticated() ? req.user._id ? req.user : req.user[0] : null
	res.render(__dirname + '/public/register.ejs', {user, csrfToken: req.csrfToken()});
})

app.get('/info', checkAuth, (req, res) => {
	res.send(JSON.stringify(req.user));
})

function checkAuth(req, res, next) {
	let user = req.isAuthenticated() ? req.user._id ? req.user : req.user[0] : null
	if(user) return next();
	if(req.method == 'POST') return res.status(403).send('You are not logged in.');
	req.session.redirectTo = req.path;
	res.redirect(`/`)
}

app.get('/.well-known/security.txt', function (req, res) {
    res.type('text/plain');
    res.send("Contact: mailto:contact@litdevs.org");
});

app.get('*', function(req, res){
	res.status(404).render(`${__dirname}/public/404.ejs`);
});

var http = require('http');

const httpServer = http.createServer(app);

httpServer.listen(87, () => {
	console.log('HTTP Server running on port 87');
});

function setEmailConfig(emailConf) {
	emailConfig = emailConf
	fs.writeFileSync(`${__dirname}/emailConfig.json`, JSON.stringify(emailConfig, null, 4))
}

module.exports = {
	setEmailConfig
}