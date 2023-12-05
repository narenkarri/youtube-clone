const nodemailer = require('nodemailer')
const { decrypt } = require('./encrypt')

const sendEmail = async options => {


  // create reusable transporter object using the default SMTP transport
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    auth: {
      user: process.env.SMTP_EMAIL,
      pass: decrypt(process.env.SMTP_PASSWORD, process.env.IV, process.env.SMTP_PASSWORD)
    }
  })

  // send mail with defined transport object
  const message = {
    from: `${process.env.FROM_NAME} <${process.env.FROM_EMAIL}>`, // sender address
    to: options.email, // list of receivers
    subject: options.subject, // Subject line
    text: options.message // plain text body
  }

  const info = await transporter.sendMail(message)

  console.log('Message sent: %s', info.messageId)
}


module.exports = sendEmail
// const SMTP_PASS = 'SKJDLJO@$&*#22362';
// console.log("DECRYPTED: "+decrypt(process.env.SMTP_PASSWORD, process.env.IV, process.env.SMTP_PASSWORD));
