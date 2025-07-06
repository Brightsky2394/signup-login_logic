const express = require('express');
const morgan = require('morgan');
const router = require('./src/routes/user.routes');

const dbConnect = require('./src/config/userDb');
const app = express();

app.use(express.json());
app.use(morgan('dev'));
app.use('/api/users/', router);

require("dotenv").config();
const port = process.env.PORT || 9080;

app.listen(port, () => {
    dbConnect();
    console.log(`Server is running on port ${port}`);
})