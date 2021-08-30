//jshint esversion:6
require('dotenv').config()
const express = require('express');
const bodyParser = require("body-parser")
const ejs = require('ejs');
const mongoose = require("mongoose");
const session = require('express-session')
const passport = require('passport');
const findOrCreate=require("mongoose-findOrCreate")
const passportLocalMongoose=require("passport-local-mongoose")
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy=require("passport-facebook").Strategy;

// const bcrypt = require('bcrypt');
// const saltRounds=10;
//const encrypt=require("mongoose-encryption");

const app = express();
app.use(express.static("public"));
app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(session({
  secret: 'little secret',
  resave: false,
  saveUninitialized: true,
  // cookie: { secure: true }// this will only be worked in https else cookie will not be set
}))
app.use(passport.initialize());
//session allows to getback the previous stored page when closed
//when we restart
app.use(passport.session());
mongoose.connect("mongodb://localhost:27017/userDB", { //to connect to mongodb database
  useNewUrlParser: true
});
mongoose.set("useCreateIndex",true);
const userschema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret:[
    {
      type: String, 

        unique: true,

        index: true
    }
  ],
  facebookId:String
}
);
userschema.plugin(findOrCreate);
userschema.plugin(passportLocalMongoose);//local login strategy .....this is to save all the user credentials into mongodb
//encryption
//userschema.plugin(encrypt,{secret:process.env.SECRET,encryptedFields:["password"]});
const User = new mongoose.model("User", userschema);
///////////////this is only used during sessions and  serialize to store user credentials and deserialize to delete
passport.use(User.createStrategy());
//passport has its own serializer and deserializer

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});


//PLACE IT AFTER SESSION AND COOCKIES TO SAVE GOOGLE SESSION
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:2000/auth/google/secrets",
     userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id}, function (err, user) {//create findOrCreate by requiring it
      return cb(err, user);
    });
  }
));
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:2000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
app.get('/auth/facebook',
  passport.authenticate('facebook', { scope: ['public_profile','email'] }));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/", function(req, res) {
  res.render("home");

})
app.get("/login", function(req, res) {
  res.render("login");

})
app.get("/auth/google",// no callback here
passport.authenticate('google', { scope: ['profile'] })
);
app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });
app.get("/register", function(req, res) {
  res.render("register");
});

  //we dont need to see only if authenticated
  // if(req.isAuthenticated()){
  //   res.render("secrets");
  // }else{
  //   res.redirect("/login");
  // };
  app.get("/secrets", function(req, res){
    User.find({"secret": {$ne: null}}, function(err, foundUsers){
      if (err){
        console.log(err);
      } else {
        if (foundUsers) {
          res.render("secrets", {usersWithSecrets: foundUsers});
        }
      }
    });
  });//this shows all secrets in our collections
app.get("/submit",function(req,res){
  if(req.isAuthenticated()){
    res.render("submit")
  }else{
    res.redirect("/login")
  }
});
app.post("/submit",function(req,res){
  const submitsecret=req.body.secret;
  var userid=req.user.id;
  User.findOneAndUpdate({_id:userid},{$push:{secret:{$each:[submitsecret]}}},function(err,found){
    if(err){
      console.log(err);
    }else{
      if(found){

        //  found.save(function(){
         // console.log( found);
           res.redirect("/secrets")
        //  });
       }
    }
  })
})
app.post("/register", function(req, res) {
  User.register({username:req.body.username},req.body.password,function(err,user){
    if(err){
      console.log(err);
      res.redirect("/register")
    }
    else{
    passport.authenticate("local")(req,res,function(){
      res.redirect("/secrets");
    });
  };
});
  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  //   // Store hash in your password DB.
  //   const newuser = new User({
  //     email: req.body.username,
  //     password:hash
  //   })
  //   newuser.save(function(err) {
  //     if (err) {
  //       console.log(err);
  //
  //     } else {
  //       res.render("secrets")
  //     }
  //   })
// });

});
// app.post("/login",function(req,res){
//   res.render("login")
//   const username=req.body.username;
//   const password=req.body.password;
// User.findOne({email:username},function(err,found){
//   if(err){
//
//     console.log(err);
//
//   }
//   else{
//     if(found ){
//         // Load hash from your password DB.
//       bcrypt.compare(password,found.password  , function(err, result) {
//         // result == true
//     });
//         res.render("secrets");
//       }
//       else{
//         res.send("User not found")
//       }
//     }
//
//
//   })
  // });
  app.post("/login", function(req, res){

    const user = new User({
      username: req.body.username,
      password: req.body.password
    });

    req.login(user, function(err){
      if (err) {
        console.log(err);
      } else {
        passport.authenticate("local")(req, res, function(){
          res.redirect("/secrets");
        });
      }
    });
});
app.get("/logout",function(req,res){
  req.logout();
  res.redirect("/");
})


app.listen(2000, function() {
  console.log("listening on port 2000");
})
