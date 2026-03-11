var express = require("express");
var router = express.Router();
let userModel = require("../schemas/users");
let { body, validationResult } = require('express-validator')


router.get("/", async function (req, res, next) {
  let users = await userModel
    .find({ isDeleted: false })
  res.send(users);
});

router.get("/:id", async function (req, res, next) {
  try {
    let result = await userModel
      .find({ _id: req.params.id, isDeleted: false })
    if (result.length > 0) {
      res.send(result);
    }
    else {
      res.status(404).send({ message: "id not found" });
    }
  } catch (error) {
    res.status(404).send({ message: "id not found" });
  }
});

router.post("/", [
  body('username').notEmpty().withMessage("username khong duoc rong").bail().isAlphanumeric().withMessage("username khong duoc chua ki tu dac biet"),
  body('email').notEmpty().withMessage("email khong duoc rong").bail().isEmail().withMessage("email sai dinh dang").normalizeEmail(),
  body('password').notEmpty().withMessage("password khong duoc rong").bail().isStrongPassword({
    minLength: 8,
    minLowercase: 1,
    minNumbers: 1,
    minSymbols: 1,
    minUppercase: 1
  }).withMessage(" password it naht 8 ki tu trong do co it nhat 1 ki tu dac biet, 1 ki tu in hoa, 1 ki tu thuong , 1 ki tu so"),
  body("avatarUrl").optional({
    checkFalsy: true
  }).isURL().withMessage("URL sai dinh dang"),
  body("role").notEmpty().withMessage("role khong duoc de trong").bail().isMongoId().withMessage("role khong hop le")
],
  function (req, res, next) {
    let result = validationResult(req);
    if (result.errors.length > 0) {
      res.status(404).send(result.errors.map(
        function (e) {
          return {
            [e.path]: e.msg
          }
        }
      ))
    } else {
      next()
    }
  }
  , async function (req, res, next) {
    try {
      let newItem = new userModel({
        username: req.body.username,
        password: req.body.password,
        email: req.body.email,
        fullName: req.body.fullName,
        avatarUrl: req.body.avatarUrl,
        status: req.body.status,
        role: req.body.role,
        loginCount: req.body.loginCount
      });

      await newItem.save();

      // populate cho đẹp
      let saved = await userModel
        .findById(newItem._id)
      res.send(saved);
    } catch (err) {
      res.status(400).send({ message: err.message });
    }
  });

router.put("/:id", async function (req, res, next) {
  try {
    let id = req.params.id;
    let updatedItem = await userModel.findByIdAndUpdate(id, req.body, { new: true });

    if (!updatedItem) return res.status(404).send({ message: "id not found" });

    let populated = await userModel
      .findById(updatedItem._id)
    res.send(populated);
  } catch (err) {
    res.status(400).send({ message: err.message });
  }
});

router.delete("/:id", async function (req, res, next) {
  try {
    let id = req.params.id;
    let updatedItem = await userModel.findByIdAndUpdate(
      id,
      { isDeleted: true },
      { new: true }
    );
    if (!updatedItem) {
      return res.status(404).send({ message: "id not found" });
    }
    res.send(updatedItem);
  } catch (err) {
    res.status(400).send({ message: err.message });
  }
});

module.exports = router;