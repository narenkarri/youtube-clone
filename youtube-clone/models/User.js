const crypto = require('crypto')
const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const argon2 = require('argon2');

const uniqueValidator = require('mongoose-unique-validator')
mongoose.set('strictQuery', true)

const Schema = mongoose.Schema

const UserSchema = new Schema(
  {
    channelName: {
      type: String,
      required: [true, 'Please add a channel name'],
      unique: true,
      uniqueCaseInsensitive: true
    },
    email: {
      type: String,
      required: [true, 'Please add an email'],
      unique: true,
      uniqueCaseInsensitive: true,
      match: [
        /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/,
        'Please add a valid email'
      ]
    },
    photoUrl: {
      type: String,
      default: 'no-photo.jpg'
    },
    role: {
      type: String,
      enum: ['user', 'admin'],
      default: 'user'
    },
    password: {
      type: String,
      required: [true, 'Please add a password'],
      validate: {
        validator: function (value) {
          // Password complexity // Password complexity check (example: requiring at least one uppercase, one lowercase, one number, one special character and a minimum length of 12 characters
          const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+{};:,<.>]).{12,}$/;
          return passwordRegex.test(value);
        },
        message: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character and be at least 12 characters long.'
      },
      select: false
    },
    resetPasswordToken: String,
    resetPasswordExpire: Date
  },
  { toJSON: { virtuals: true }, toObject: { virtuals: true }, timestamps: true }
)

UserSchema.index({ channelName: 'text' })

UserSchema.virtual('subscribers', {
  ref: 'Subscription',
  localField: '_id',
  foreignField: 'channelId',
  justOne: false,
  count: true,
  match: { userId: this._id }
})
UserSchema.virtual('videos', {
  ref: 'Video',
  localField: '_id',
  foreignField: 'userId',
  justOne: false,
  count: true
})

UserSchema.plugin(uniqueValidator, { message: '{PATH} already exists.' })

UserSchema.pre('find', function () {
  this.populate({ path: 'subscribers' })
})

// Ecrypt Password
UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    next()
  }

  // const salt = await bcrypt.genSalt(10)
  this.password = await argon2.hash(this.password)
})

UserSchema.methods.matchPassword = async function (enteredPassword) {
  // return await bcrypt.compare(enteredPassword, this.password)
  return await argon2.verify(this.password,enteredPassword)
}

UserSchema.methods.getSignedJwtToken = function () {
  return jwt.sign({ id: this._id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRE
  })
}

UserSchema.methods.getResetPasswordToken = function () {
  // Generate token
  const resetToken = crypto.randomBytes(20).toString('hex')

  // Hash token and set to resetPasswordToken field
  this.resetPasswordToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex')

  // Set expire
  this.resetPasswordExpire = Date.now() + 10 * 60 * 1000

  return resetToken
}

module.exports = mongoose.model('User', UserSchema)
