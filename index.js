const express = require("express");
const JsonDB = require('node-json-db').JsonDB;
const Config = require('node-json-db/dist/lib/JsonDBConfig').Config;
const uuid = require('uuid');
const speakeasy = require('speakeasy');

const app = express()

const db = new JsonDB(new Config("myDataBase", true, false, '/'));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get('/api', (req,res) => {
    res.json({message: "Welcome to two factor authentication example"})
});

// Register user & create temp secret 
app.post("/api/register", (req,res)=>{
  const id = uuid.v4();
  try {
    const path = `/user/${id}`;
    // Create temporary secret until it it verified
    const temp_secret = speakeasy.generateSecret();
    // Create user in the database
    db.push(path,{id, temp_secret});
    // Send user id and base32 key to user
    res.json({id,secret: temp_secret.base32});
  } catch (error) {
    console.log(error);
    res.status(500).json({message: 'Error generating the secret key'})
  }
});

//Verify token and make secret perm
app.post("/api/verify", async (req,res)=>{
  const { userId, token }= req.body;
  try {
    // Retrieve user from database
    const path = `/user/${userId}`;
    const user = await db.getData(path);
    const { base32: secret } = user.temp_secret;
    const verified = speakeasy.totp.verify({
    secret,
    encoding: 'base32',
    token
  });
  if(verified){
    // Update user data
    db.push(path, {id: userId, secret: user.temp_secret});
    res.json({ verified:true });
    } else {
      res.json({ verified:false });
    }
    } catch (error) {
      res.status(500).json({message: 'Error retrieving user'});
    }
});


app.post("/api/validate", async (req,res) => {
  var { userId, token } = req.body;
  try {
    // Retrieve user from database
    const path = `/user/${userId}`;
    const user = await db.getData(path);
    const { base32: secret } = user.secret;
    // Returns true if the token matches
    const tokenValidates = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: 1
    });
    if (tokenValidates) {
      res.json({ validated: true });
    } else {
      res.json({ validated: false});
    }
  } catch(error) {
    console.error(error);
    res.status(500).json({ message: 'Error retrieving user'});
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, ()=> console.log(`Server running on port ${PORT}`));