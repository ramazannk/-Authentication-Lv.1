import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt"
import passport from "passport"
import { Strategy } from "passport-local";
import session from "express-session";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;

app.use(session({
  secret: "MYFIRSTLOVE",
  resave: false,
  saveUninitialized: true
}))

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "secrets",
  password: "00071200",
  port: 5432,
});
db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});
app.get("/secrets", (req, res) => {
  if(req.isAuthenticated()){
    res.render("secrets.ejs")
  }else{
    res.redirect("/login")
  }
})

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;
  console.log(email)
  console.log(password)
  try{
    const checkEmail = await db.query("SELECT * FROM users WHERE email = $1", [email])
    if(checkEmail.rows.length > 0){
      res.send("You email already excisit please try an other email")
    }else{
      bcrypt.hash(password, saltRounds, async(err, hash) =>{
        if(err){
          console.log("something went wrong: " , err);
        }else{
          await db.query("INSERT INTO users(email, password) VALUES($1, $2)", [email, hash])
          res.render("secrets.ejs")
        }
      })
    }
  }catch(err){
    console.log(err)
  }
});

passport.use(
  new Strategy(async function verify (username, password, cb){
    const email = req.body.username;
    const liginPassword = req.body.password;
    try{
      const checkEmail = await db.query("SELECT * FROM users WHERE email = $1", [username])
      if(checkEmail.rows.length > 0){
  
        const user = checkEmail.rows[0];
        const postPasswor = user.password
  
        bcrypt.compare(password, postPasswor, (err, hushRes) => {
          if(err){
            console.log("incorrect please try again: ", err)
          }else{
            if(hushRes){
              return cb(null, user)
            }else{
              return cb(null, false)
            }
          }
        })
      }else{
        res.send("not found email")
      }
    }catch(err){
      console.log(err)
    }
  })
)

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
