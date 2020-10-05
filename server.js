const express = require("express");
const router = express.Router();
const Users = require("./users");
const bcrpyt = require("bcrypt");
const jwt = require("jsonwebtoken");

const protected = async (req, res, next) => {
  if (req.session && req.session.userId) next();
  else res.status(401).send("Na duude");
};

const validateNewUser = async (req, res, next) => {
  if (!req.body)
    return res.status(400).json({ message: "Invalid new user data" });

  const { username, password, department } = req.body;
  if (!username || !password || !department)
    return res.status(400).json({ message: "Missing new user data" });
  req.newUser = { username, password, department };
  next();
};

const generateToken = (user) => {
  const payload = {
    subject: user.id,
    username: user.username,
    department: user.department,
  };

  const options = {
    expiresIn: "1w",
  };

  return jwt.sign(payload, process.env.JWT_SECRET, options);
};

const server = express();

server.use(express.json());

router.get("/api/users", async (req, res) => {
  try {
    const users = await Users.findByDepartment(req.user.department);
    res.status(200).json(users);
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: err });
  }
});

router.post("/api/register", validateNewUser, async (req, res) => {
  const { newUser } = req;
  newUser.password = await bcrpyt.hash(newUser.password, 10);
  try {
    const user = await Users.add(newUser);
    if (!user)
      res.status(500).json({ message: "There was an error registering" });
    res
      .status(200)
      .json({ message: "You have registered, you can now log in." });
  } catch (err) {
    if (err.message.includes("UNIQUE constraint"))
      return res.status(500).json({ message: "That user already exists" });
    return res.status(500).json({ message: err.message });
  }
});

router.post("/api/login", async (req, res) => {
  if (!req.body)
    return res.status(400).json({ message: "Missing login information" });

  const { login, password } = req.body;

  if (!login || !password)
    return res.status(400).json({
      message: "Please provide a username (or email) and password to log in",
    });

  try {
    const user = await Users.findByLogin(login);
    if (!user || !(await bcrpyt.compare(password, user.password)))
      return res.status(400).json({
        message: "Invalid credentials",
      });
    const token = generateToken(user);
    return res.status(200).json({ message: "success", token });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Could not log in" });
  }
});

server.use("/api/users", (req, res, next) => {
  const { authorization } = req.headers;
  if (!authorization) return res.status(401).send("You shall not pass!");
  try {
    const decoded = jwt.verify(
      authorization.replace("Bearer ", ""),
      process.env.JWT_SECRET
    );
    if (
      !decoded ||
      !decoded.username ||
      !decoded.subject ||
      !decoded.department
    )
      return res.status(401).send("Na duude");
    req.user = {
      id: decoded.subject,
      username: decoded.username,
      department: decoded.department,
    };
    next();
  } catch (err) {
    console.log(err);
    return res.status(401).send("Invalid signature");
  }
});

server.use(router);

module.exports = server;
