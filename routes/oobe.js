var express = require('express')
    , app = require('../app')
    , router = express.Router();

let emailTestConfig
router.post("/oobe/emailConfig", (req, res) => {
    if (!req.body?.smtp_hostname || !req.body?.smtp_port || typeof req.body?.smtp_secure === "undefined" || !req.body?.email_sender || !req.body?.email_from) return res.status(400).send({type: "error", message: "Please fill out all fields"});
    if (req.body?.smtp_password && !req.body?.smtp_username) return res.status(400).send({type: "error", message: "Please fill out all fields"});
    res.sendStatus(200)
    emailTestConfig = req.body
})

let emailTested = false
router.post("/oobe/emailTest", (req, res) => {
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

router.get("/oobe/emailFinal", (req, res) => {
    if(!emailTestConfig) return res.status(400).send({type: "error", message: "Successfully finish configuring the email settings first"})
    let mailerConfig = {
        host: emailTestConfig.smtp_hostname,
        port: emailTestConfig.smtp_port,
        secure: emailTestConfig.smtp_secure
    }
    if(emailTestConfig?.smtp_username) mailerConfig.auth = { user: emailTestConfig.smtp_username }
    if(emailTestConfig?.smtp_password) mailerConfig.auth.pass = emailTestConfig.smtp_password
    let emailConfig = {
        mailerConfig: {
            ...mailerConfig
        },
        sender: `"${emailTestConfig.email_sender}" <${emailTestConfig.email_from}>`
    }
    app.setEmailConfig(emailConfig)
    res.sendStatus(200)
})
 
module.exports = router;