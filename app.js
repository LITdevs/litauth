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
  , nodemailer = require("nodemailer");
require("dotenv").config();
const MongoDBStore = require("connect-mongodb-session")(session);

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

app.post("/login/register", (req, res) => {
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
})

let emailTestConfig
app.post("/oobe/emailConfig", (req, res) => {
	if (!req.body?.smtp_hostname || !req.body?.smtp_port || typeof req.body?.smtp_secure === "undefined" || !req.body?.email_sender || !req.body?.email_from) return res.status(400).send({type: "error", message: "Please fill out all fields"});
	if (req.body?.smtp_password && !req.body?.smtp_username) return res.status(400).send({type: "error", message: "Please fill out all fields"});
	res.sendStatus(200)
	emailTestConfig = req.body
})

let emailTested = false
app.post("/oobe/emailTest", (req, res) => {
	if(!emailTestConfig) return res.status(400).send({type: "error", message: "Submit your email config first"})
	if(!req.body.test_address) return res.status(400).send({type: "error", message: "Please fill out all fields"})
	let mailerConfig = {
		host: emailTestConfig.smtp_hostname,
		port: emailTestConfig.smtp_port,
		secure: emailTestConfig.smtp_secure
	}
	if(emailTestConfig?.smtp_username) mailerConfig.auth = { user: emailTestConfig.smtp_username }
	if(emailTestConfig?.smtp_password) mailerConfig.auth.pass = emailTestConfig.smtp_password
	let transporter = nodemailer.createTransport(mailerConfig);
	transporter.verify(function (error, success) {
		if (error) {
			console.error(error);
			res.send({type: "emailError", message: "Possibly invalid email config", error: error.message})
		} else {
			transporter.sendMail({
				from: `"${emailTestConfig.email_sender}" <${emailTestConfig.email_from}>`,
				to: req.body.test_address,
				subject: "LITauth Email Test",
				html: "<html><body>Congratulations! You've successfully configured your email settings!<br><br><a href='https://litdevs.org/vsite/laughskelly.mp3'>Enjoy your reward</a></body></html>"
			}, (err, info) => {
				if (err) {
					console.error(err);
					res.send({type: "emailError", message: "Possibly invalid email config", error: err, info})
				} else {
					if (info.accepted.includes(req.body.test_address)) {
						emailTested = true
						return res.send({type: "success", message: "Email test successful", info})
					} else {
						if (info.pending.includes(req.body.test_address)) {
							emailTested = true
							return res.send({type: "emailPending", message: "Email not accepted yet, it may have worked, or may have not.", error: JSON.stringify(info.pending), info})
						}
						if (info.rejected.includes(req.body.test_address)) {
							return res.send({type: "emailRejected", message: "Email rejected by the destination server", info})
						}
						emailTested = true
						res.send({type: "error", message: "Unknown error, if you received the email, continue to the next step", info})
					}
				}
			})
		}
	});
})

app.get("/oobe/emailFinal", (req, res) => {
	if(!emailTestConfig) return res.status(400).send({type: "error", message: "Successfully finish configuring the email settings first"})
	let mailerConfig = {
		host: emailTestConfig.smtp_hostname,
		port: emailTestConfig.smtp_port,
		secure: emailTestConfig.smtp_secure
	}
	if(emailTestConfig?.smtp_username) mailerConfig.auth = { user: emailTestConfig.smtp_username }
	if(emailTestConfig?.smtp_password) mailerConfig.auth.pass = emailTestConfig.smtp_password
	emailConfig = {
		mailerConfig: {
			...mailerConfig
		},
		sender: `"${emailTestConfig.email_sender}" <${emailTestConfig.email_from}>`
	}
	fs.writeFileSync(`${__dirname}/emailConfig.json`, JSON.stringify(emailConfig, null, 4))
	res.sendStatus(200)
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