const express = require("express");
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");
const passport = require("passport");
const flash = require("express-flash");
const session = require("express-session");
require("dotenv").config();
const webpush=require('web-push')
const app = express();

const PORT = process.env.PORT || 3000;

const initializePassport = require("./passportConfig");

initializePassport(passport);


app.use(express.urlencoded({ extended: true }));
app.set("view engine", "ejs");

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  })
);

app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

app.get("/", (req, res) => {
  res.render("index");
});

app.get("/users/register", checkAuthenticated, (req, res) => {
  res.render("register.ejs");
});

app.get("/users/login", checkAuthenticated, (req, res) => {

  console.log(req.session.flash.error);
  res.render("login.ejs");
});


app.get("/users/dashboard", checkNotAuthenticated, (req, res) => {
  console.log(req.isAuthenticated());
  const id=parseInt(req.user.id);
  console.log(id)
  pool.query(
    `select details,date,time from meeting
     inner join users
     on users.id=meeting.u_id
     where meeting.u_id=${id}
     order by date,time 
     ` ,
     (err,results)=>{
     if(err)
        console.log(err)
      else{
         res.render("dashboard", {rows:results.rows});
      }
     }
  )
 
});

app.post("/users/dashboard",async(req,res)=>{
  let {date, time, details}=req.body;
  let id=parseInt(req.user.id)

  console.log(req.user.id)
  pool.query(
    ` insert into meeting(date,time,details,u_id)  
      VALUES ($1, $2, $3, $4)`,
      [date,time,details,id],
      (err,results)=>{
        if(err)
          throw err;
        else 
          res.redirect('/users/dashboard')
      }
    )
  
})
app.get('/users/dashboard/new',function(req,res){
  // console.log(req.user.id)
    res.render('new',{user:req.user.id})
})

app.get("/users/logout", (req, res) => {
  req.logout();
  res.render("index", { message: "You have logged out successfully" });
});

app.post("/users/register", async (req, res) => {
  let { name, email, password, password2 } = req.body;

  let errors = [];

  // console.log({
  //   name,
  //   email,
  //   password,
  //   password2
  // });

  if (!name || !email || !password || !password2) {
    errors.push({ message: "Please enter all fields" });
  }

  if (password.length < 6) {
    errors.push({ message: "Password must be a least 6 characters long" });
  }

  if (password !== password2) {
    errors.push({ message: "Passwords do not match" });
  }

  if (errors.length > 0) {
    res.render("register", { errors, name, email, password, password2 });
  } else {
    hashedPassword = await bcrypt.hash(password, 10);
    console.log(hashedPassword);
    // Validation passed
    pool.query(
      `SELECT * FROM users
        WHERE email = $1`,
      [email],
      (err, results) => {
        if (err) {
          console.log(err);
        }
        // console.log(results.rows);

        if (results.rows.length > 0) {
          return res.render("register", {
            message: "Email already registered"
          });
        } else {
          pool.query(
            `INSERT INTO users (name, email, password)
                VALUES ($1, $2, $3)
                RETURNING id, password`,
            [name, email, hashedPassword],
            (err, results) => {
              if (err) {
                console.log(err);
              }
              // console.log(results.rows);
              req.flash("success_msg", "You are now registered. Please log in");
              res.redirect("/users/login");
            }
          );
        }
      }
    );
  }
});

app.post(
  "/users/login",
  passport.authenticate("local", {
    successRedirect: "/users/dashboard",
    failureRedirect: "/users/login",
    failureFlash: true
  })
);

function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect("/users/dashboard");
  }
  next();
}

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/users/logout");
}

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

