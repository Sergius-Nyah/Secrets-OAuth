require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const bcrypt = require('bcrypt');
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require('passport-local').Strategy;
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate'); 

const saltRounds = 10;

const app = express(); 

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true });

const userSchema = new mongoose.Schema({
    username: String,
    password: String, 
    secret: String
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate); 

const User = new mongoose.model('User', userSchema);

passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/register", function(req, res){
    if(req.isAuthenticated()){
        res.render('secrets');
    } else{ 
        res.render('register');
    }
});
app.get("/register", function(req, res){
    User.find({"secrets":{$ne:null}, function(err, foundUsers){
        if(err){
            console.log(err)
        }else{
            if(foundUsers){
                res.render("secrets", {usersWithSecrets: foundUsers});
            }
        }
    }});
})

app.post('/register', async (req, res) => {
    const newUser = new User({
        username: req.body.username,
    });

    try {
        await User.register(newUser, req.body.password);
        passport.authenticate("local")(req, res, function () {
            res.redirect("/secrets");
        });
    } catch (err) {
        console.log(err);
        res.status(500).send('Internal Server Error');
    }
});

app.get("/submit", function(req, res){
    if(req.isAuthenticated()){
        res.render('submit');
    } else{ 
        res.redirect('/login');
    }
});
app.post("/submit", function(req, res){
    const submittedSecret= req.body.secret;
    console.log(req.user.id);

    User.findById(req.user.id, function(err, foundUser){
        if(err){
            console.log(err)
        }else{
            if(foundUser){
                foundUser.secret = submittedSecret;
                foundUser.save(function(){
                    res.redirect("/secrets");
                });
            }
        }
    })
})

app.post('/login', passport.authenticate("local"), (req, res) => { //cookie. 
    res.redirect("/secrets");
});

app.get('/', function (req, res) {
    res.render("home");
});

app.get("/auth/google", function(req, res){
    passport.authenticate("google", { scope: ["profile"] });
    res.redirect("/"); // Add this line to actually redirect the user
});
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });
 
app.get('/login', function (req, res) {
    res.render("login");
});

app.get('/secrets', function (req, res) {
    if (req.isAuthenticated()) {
        res.render("secrets");
    } else {
        res.redirect("/login");
    }
});

app.get('/logout', function(req, res){
    req.logout();
    res.redirect('/'); // Change this line to actually redirect the user
})

app.get('/submit', function (req, res) {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.listen(3000, () => {
    console.log(`Server running on port 3000!`);
});
