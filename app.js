const express = require("express");
const app = express();

const mongoose = require("mongoose");
const passport = require("passport");
const bodyParser = require("body-parser");
const LocalStrategy = require("passport-local");
const User = require("./models/user");
xss = require("xss-clean");
helmet = require("helmet");
rateLimit = require("express-rate-limit");
const { check, validationResult } = require("express-validator");
mongoSanitize = require("express-mongo-sanitize");

const passportLocalMongoose = require("passport-local-mongoose");
mongoose.connect("mongodb://mongo_camp:27017/auth_demo");

const expSession = require("express-session")({
  secret: "supersecret",
  resave: false,
  saveUninitialized: true,
  cookie: {
    httpOnly: true,
    secure: true,
    maxAge: 2 * 60 * 1000,
  },
});

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());
passport.use(new LocalStrategy(User.authenticate()));

app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(expSession);
app.use(express.static("public"));

app.use(mongoSanitize());

const limit = rateLimit({
  max: 100,
  windowMs: 60 * 60 * 1000,
  message: "request limit reached",
});

app.use(express.json({ limit: "12kb" }));
app.use(xss());
app.use(helmet());

app.get("/", limit, (req, res) => {
  res.render("home");
});
app.get("/userprofile", limit, (req, res) => {
  res.render("userprofile");
});

app.get("/login", limit, (req, res) => {
  res.render("login");
});
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/userprofile",
    failureRedirect: "/login",
  }),
  limit,
  function (req, res) {}
);
app.get("/register", limit, (req, res) => {
  res.render("register");
});

app.post(
  "/register",
  [
    check("phone").isLength({ min: 10 }).withMessage("Enter a valid phone"),
    check("email").isLength({ min: 1 }).withMessage("Enter an email"),
    check("username").isLength({ min: 1 }).withMessage("Enter username"),
    check("password")
      .isLength({ min: 10 })
      .withMessage("Enter 10 chars long password")
      .matches(/\d/)
      .withMessage("Make sure you have numbers in password")
      .matches(/[!@#$%^&*(),.?":{}|<>]/)
      .withMessage("Make sure you have numbers in special character"),
  ],
  limit,
  (req, res) => {
    const errors = validationResult(req);
    if (errors.isEmpty()) {
      User.register(
        new User({
          username: req.body.username,
          email: req.body.email,
          phone: req.body.phone,
        }),
        req.body.password,
        function (err, user) {
          if (err) {
            console.log(err);
            res.render("register");
          }
          passport.authenticate("local")(req, res, function () {
            res.redirect("/login");
          });
        }
      );
    } else {
      console.log(errors.array());
      res.render("register", {
        errors: errors.array(),
        data: req.body,
      });
    }
  }
);
app.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});

function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login");
}

app.listen(process.env.PORT || 3000, function (err) {
  if (err) {
    console.log(err);
  } else {
    console.log("Server listning to Port 3000");
  }
});
