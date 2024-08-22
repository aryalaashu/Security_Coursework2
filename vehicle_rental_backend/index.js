const express = require('express');
require('dotenv').config();
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const https = require('https');
const connectDB = require('./configs/db.config');
const userModel = require('./modules/users/user.model');

const app = express();
const session = require('express-session');

connectDB().then(
  async () => {
    const checkSuperAdmin = await userModel.findOne({
      email: "superadmin@vehicle.com",
      role: "superadmin"
    });
    if (!checkSuperAdmin) {
      //create Admin
      await userModel.create({
        email: "superadmin@vehicle.com",
        role: "superadmin",
        firstname: "Super",
        lastname: "Admin",
        password: "$2a$10$YL1LurPkeUu41HWk1bMg8uSOxY6ScQYF0M44eqNUl6LhO5t06uaTy"
      });
    }
  }
).catch(
  async (err) => {
    console.log("errrr:", err);
  }
);

// Enable CORS with proper configuration
app.use(
  cors({
    origin: function (origin, callback) {
      const allowedOrigins = process.env.URL;

      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true
  })
);

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET, 
  resave: false,                       
  saveUninitialized: false,            
  cookie: {
      secure: process.env.NODE_ENV === 'production', 
      httpOnly: true,                            
      maxAge: 300000                                 
  }
}));

app.use(express.json({ limit: '50mb' }));
app.use(
  express.urlencoded({
    extended: false,
    limit: '50mb'
  })
);

// Serve static files
app.use(express.static(path.join(__dirname, '/')));

// Define a default route to check if the server is connected
app.get('/', (req, res) => {
  res.send('Connected...');
});

// Define your routes using Express Router
app.use('/api', require("./routes/index"));

const port = process.env.PORT || 8888;
const url = process.env.URL;
const env = process.env.ENV;
const app_name = process.env.APP_NAME;

app.set('PORT', port);

// Read SSL certificate and key
const sslOptions = {
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem')
};

// Create HTTPS server
// https.createServer(sslOptions, app).listen(port, () => {
  app.listen(port, () => {
  console.log(`Server is starting at port ${port} || SUCCESS`);
  console.log(`Hosting at https://${url}:${port} || SUCCESS`);
  // console.log(`${app_name} is running on env ${env} || SUCCESS`);
  console.log(
    '--------------------------------------------------------------------------------------------------------------------------------------------------'
  );
});
