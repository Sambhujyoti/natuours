const mongoose = require('mongoose');
const dotenv = require('dotenv');
dotenv.config({ path: './config.env' });

const app = require('./app');

const DB = process.env.DATABASE.replace(
  '<PASSWORD>',
  process.env.DATABASE_PASSWORD,
);

mongoose
  .connect(DB)
  .then(() =>
    console.log('Database Cloud connection is successful! 💻<----✅---->🖥️'),
  );

// console.log(process.env);

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(
    `App is running at port ${port} on ${process.env.NODE_ENV} server....`,
  );
});
