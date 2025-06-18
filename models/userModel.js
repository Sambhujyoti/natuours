const crypto = require('crypto');
const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const { Schema } = mongoose;

const userSchema = new Schema({
  name: {
    type: String,
    required: [true, 'Please enter an user name!'],
    maxlength: [40, 'An user name must be within 40 characters!'],
    minlength: [10, 'An user name must have atleast 10 characters!'],
  },
  email: {
    type: String,
    required: [true, 'Please enter your email address!'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please enter a valid email address!'],
  },
  photo: {
    type: String,
  },
  role: {
    type: String,
    enum: ['user', 'guide', 'lead-guide', 'admin'],
    default: 'user',
  },
  password: {
    type: String,
    required: [true, 'Please enter a valid password!'],
    minlength: [8, 'A password must have atleast 8 characters!'],
    select: false,
  },
  passwordConfirm: {
    type: String,
    required: [true, 'Please confirm your password.'],
    validate: {
      // This only works to CREATE and SAVE!
      validator: function (el) {
        return el === this.password;
      },
      message: 'The given password is different!',
    },
  },
  passwordChangedAt: {
    type: Date,
  },
  passwordResetToken: {
    type: String,
  },
  passwordResetExpired: {
    type: Date,
  },
  active: {
    type: Boolean,
    default: true,
    select: false,
  },
});

userSchema.pre('save', async function (next) {
  // Only run this function if password has actually modified.
  if (!this.isModified('password')) return next();

  // Hash the password with the const of 12
  this.password = await bcrypt.hash(this.password, 12);

  // Delete confirmation field.
  this.passwordConfirm = undefined;
  next();
});

userSchema.pre('save', function (next) {
  if (!this.isModified('password') || this.isNew) return next();
  this.passwordChangedAt = Date.now() - 1000;
  next();
});

userSchema.pre(/^find/, function (next) {
  // This points to current document
  this.find({ active: { $ne: false } });
  next();
});

userSchema.methods.correctPassword = async function (
  candidatePassword,
  userPassword,
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10,
    );
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString('hex');
  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  // console.log({ resetToken }, this.passwordResetToken);

  this.passwordResetExpired = Date.now() + 10 * 60 * 1000;

  return resetToken;
};

const User = mongoose.model('User', userSchema);

module.exports = User;
