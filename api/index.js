const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const morgan = require("morgan");
const cors = require("cors");

app.use(express.json());
app.use(morgan("dev"));
app.use(cors());

const users = [
  {
    id: "1",
    username: "john",
    password: "John0908",
    isAdmin: true,
  },
  {
    id: "2",
    username: "jane",
    password: "Jane0908",
    isAdmin: false,
  },
];

let refreshTokens = [];

const generateAccessToken = (user) => {
  const accessToken = jwt.sign(
    { id: user.id, isAdmin: user.isAdmin },
    "mySecretKey",
    {
      expiresIn: "5s",
      // expiresIn: "15m"
    }
  );
  return accessToken;
};

const generateRefreshToken = (user) => {
  const refreshToken = jwt.sign(
    { id: user.id, isAdmin: user.isAdmin },
    "myRefreshSecretKey"
  );
  return refreshToken;
};

app.post("/api/refresh", (req, res) => {
  // take the refresh token from the user
  const refreshToken = req.body.token;

  // send error if there is no token or it's invalid
  if (!refreshToken) {
    return res.status(401).json("You are not authenticated!");
  }

  if (!refreshTokens.includes(refreshToken)) {
    return res.status(403).json("Refresh token is not valid!");
  }

  jwt.verify(refreshToken, "myRefreshSecretKey", (err, user) => {
    err && console.log(err);
    refreshTokens = refreshTokens.filter((token) => token !== refreshToken);

    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);

    refreshTokens.push(newRefreshToken);

    res.status(200).json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  });
  // if everything is ok, create new access token, refresh token and send to user
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  // console.log(username, password);
  const user = users.find((u) => {
    return u.username === username && u.password === password;
  });
  if (user) {
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    refreshTokens.push(refreshToken);
    res.json({
      username: user.username,
      isAdmin: user.isAdmin,
      accessToken,
      refreshToken,
    });
  } else {
    res.status(400).json("Username or password incorrect!");
  }
});

const verify = (req, res, next) => {
  const authHeader = req.headers.authorization;
  // console.log(authHeader);
  if (authHeader) {
    const token = authHeader.split(" ")[1];
    jwt.verify(token, "mySecretKey", (err, user) => {
      if (err) {
        return res.status(403).json("Token is not valid!");
      }
      req.user = user;
      next();
    });
  } else {
    res.status(401).json("You are not authenticated");
  }
};

app.delete("/api/users/:userId", verify, (req, res) => {
  if (req.user.id === req.params.userId || req.user.isAdmin) {
    res.status(200).json("User has been deleted!");
  } else {
    res.status(403).json("You are not allowed to delete this user!");
  }
});

app.post("/api/logout", verify, (req, res) => {
  const refreshToken = req.body.token;
  refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
  res.status(200).json("You logged out successfully");
});

app.listen(5000, () => console.log("Backend server is running on port:", 5000));
