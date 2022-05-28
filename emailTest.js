const nodemailer = require("nodemailer");
require("dotenv").config();
const fs = require("fs");
let transporter = nodemailer.createTransport({
    host: "mail.wanderers.cloud",
    port: 465,
    secure: false,
    auth: {
        user: "litauth",
        pass: process.env.EMAIL_PASS
    },
});

transporter.sendMail({
    from: '"LITauth" <litauth@litdevs.org>',
    bcc: "contact@litdevs.org",
    subject: "LITauth Account Verification",
    html: fs.readFileSync("./email/verification.html", "utf8").toString()
});
