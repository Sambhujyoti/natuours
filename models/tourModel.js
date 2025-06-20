const mongoose = require('mongoose');
const slugify = require('slugify');
const validator = require('validator');
const { Schema } = mongoose;
// const User = require('./userModel');

// Mongoose Schema

const tourSchema = new Schema(
  {
    name: {
      type: String,
      required: [true, 'A tour must have a name!'],
      unique: [true, 'The mentioned name is already in use!'],
      trim: true,
      maxlength: [40, 'A tour name must be within 40 characters!'],
      minlength: [10, 'A tour name must have atleast 10 characters!'],
      // validate: [validator.isAlpha, 'Tour name should not contain any special character!']
    },
    slug: String,
    duration: {
      type: Number,
      require: [true, 'A tour must have a trip duration!'],
    },
    maxGroupSize: {
      type: Number,
      required: [true, 'Maximum group size must be defined!'],
    },
    ratingsAverage: {
      type: Number,
      default: 4.5,
      max: [5, 'Rating should not exceed 5.0!'],
      min: [1, 'Rating should be atleast 1.0!'],
      set: (val) => Math.round(val * 10) / 10,
    },
    ratingsQuantity: {
      type: Number,
      default: 0,
    },
    difficulty: {
      type: String,
      required: [true, 'A tour must have a difficulty level specified!'],
      enum: {
        values: ['easy', 'medium', 'difficult'],
        message: 'Difficulty should be only: easy, medium or difficult!',
      },
    },
    price: {
      type: Number,
      required: [true, 'Price should be included!'],
    },
    priceDiscount: {
      type: Number,
      validate: {
        validator: function (val) {
          // "this" only points to the current document on new creation
          return val < this.price;
        },
        message:
          'The discount value {VALUE} should be less then the tour price!',
      },
    },
    summary: {
      type: String,
      trim: true,
      required: [true, 'A tour should have a summary!'],
    },
    description: {
      type: String,
      trim: true,
    },
    imageCover: {
      type: String,
      required: [true, 'A tour must have a cover image!'],
    },
    images: [String],
    createdAt: {
      type: Date,
      default: Date.now(),
    },
    startDates: [Date],
    secretTour: {
      type: Boolean,
      default: false,
    },
    startLocation: {
      // GeoJSON
      type: {
        type: String,
        default: 'Point',
        enum: ['Point'],
      },
      coordinates: [Number],
      address: String,
      description: String,
    },
    locations: [
      {
        type: {
          type: String,
          default: 'Point',
          enum: ['Point'],
        },
        coordinates: [Number],
        address: String,
        description: String,
        day: Number,
      },
    ],
    guides: [
      {
        type: mongoose.Schema.ObjectId,
        ref: 'User',
      },
    ],
  },
  {
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  },
);

// tourSchema.index({ price: 1 });
tourSchema.index({ price: 1, ratingsAverage: -1 });
tourSchema.index({ slug: 1 });
tourSchema.index({ startLocation: '2dsphere' });

tourSchema.virtual('durationWeeks').get(function () {
  return this.duration / 7;
});

// Virtual populate
tourSchema.virtual('reviews', {
  ref: 'Review',
  foreignField: 'tour',
  localField: '_id',
});

// Document Middleware: runs before .save() and .create()

tourSchema.pre('save', function (next) {
  this.slug = slugify(this.name, { lower: true });
  next();
});

// tourSchema.pre('save', async function (next) {
//   const guidesPromises = this.guides.map(async (id) => await User.findById(id));
//   this.guides = await Promise.all(guidesPromises);
//   next();
// });

// tourSchema.post('save', function(doc, next) {
//     console.log(doc);
//     next();
// });

// Query Middleware

// tourSchema.pre('find', function(next) {
tourSchema.pre(/^find/, function (next) {
  this.find({ secretTour: { $ne: true } });
  this.start = Date.now();
  next();
});

tourSchema.pre(/^find/, function (next) {
  this.populate({
    path: 'guides',
    select: '-__v -passwordChangedAt',
  });
  next();
});

tourSchema.post(/^find/, function (docs, next) {
  console.log(`Query took ${Date.now() - this.start} milliseconds.`);
  // console.log(docs);
  next();
});

// Aggregation Middleware

// tourSchema.pre('aggregate', function (next) {
//   this.pipeline().unshift({ $match: { secretTour: { $ne: true } } });
//   console.log(this.pipeline());
//   next();
// });
const Tour = mongoose.model('Tour', tourSchema);

module.exports = Tour;
