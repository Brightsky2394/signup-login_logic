const mongoose = require('mongoose');

const dbConnect = async () => {
    await mongoose.connect(process.env.DB_URI || "your-connection-string")
     .then(() => {
        console.log("Database successfully connected");
     })
     .catch(
        (err) => {
            console.log("Unable to connect to Database\n", err.message);
        }
     )
} 

module.exports = dbConnect;