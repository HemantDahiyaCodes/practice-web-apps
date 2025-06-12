const path = require("node:path");
const { Pool } = require("pg");
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const passportStrategy = require("passport-local").Strategy;
const bcrypt = require("bcryptjs");

const pool = new Pool({
  host: "localhost",
  user: "postgres",
  database: "authentication",
  password: "Hemant",
  port: 5432,
});

// Initializing the express app
const app = express();

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(
  session({
    secret: "cats",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.session());
app.use(express.urlencoded({ extended: true }));

// Setting up passport's localStrategy
passport.use(
  new passportStrategy(async (username, password, done) => {
    try {
      const { rows } = await pool.query(
        "SELECT * FROM userInfo WHERE username = $1",
        [username]
      );
      const user = rows[0];

      // If the user is not found or is incorrect
      if (!user) {
        return done(null, false, { message: "Incorrect Username." });
      }

      // If the user is found but the password is incorrect
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        // passwords do not match!
        return done(null, false, { message: "Incorrect password" });
      }

      // If everything is right then return the user
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

// SerializeUser
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize a user
passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query("SELECT * FROM userInfo WHERE id= $1", [
      id,
    ]);
    const user = rows[0];

    done(null, user);
  } catch (err) {
    done(null, err);
  }
});

// home page
app.get("/", (req, res) => res.render("index", { user: req.user }));
app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
  })
);
app.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    return next(err);
  });

  res.redirect("/");
});

// Sign up section
app.get("/sign-up", (req, res) => res.render("sign-up-form"));
app.post("/sign-up", async (req, res, next) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    await pool.query(
      "INSERT INTO userInfo (username, password) VALUES ($1, $2)",
      [req.body.username, hashedPassword]
    );
    res.redirect("/");
  } catch (err) {
    return next(err);
  }
});

const PORT = 8000;
app.listen(PORT, () => console.log("server started at port number: ", PORT));
