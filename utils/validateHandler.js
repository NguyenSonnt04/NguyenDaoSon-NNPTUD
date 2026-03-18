let { body, validationResult } = require('express-validator')
module.exports = {
    validatedResult: function (req, res, next) {
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
    },
    CreateAnUserValidator: [
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
    ChangePasswordValidator: [
        body('oldPassword')
            .notEmpty().withMessage("oldPassword khong duoc de trong"),
        body('newPassword')
            .notEmpty().withMessage("newPassword khong duoc de trong")
            .bail()
            .isStrongPassword({
                minLength: 8,
                minLowercase: 1,
                minNumbers: 1,
                minSymbols: 1,
                minUppercase: 1
            }).withMessage("newPassword it nhat 8 ky tu, gom it nhat: 1 chu hoa, 1 chu thuong, 1 so, 1 ky tu dac biet")
            .bail()
            .custom((value, { req }) => {
                if (value === req.body.oldPassword) {
                    throw new Error("newPassword khong duoc trung voi oldPassword");
                }
                return true;
            })
    ],
    ModifyAnUser: [
        body('username').isEmpty().withMessage("khong duoc thay doi username"),
        body('email').isEmpty().withMessage("email khong thay doi"),
        body('password').optional().isStrongPassword({
            minLength: 8,
            minLowercase: 1,
            minNumbers: 1,
            minSymbols: 1,
            minUppercase: 1
        }).withMessage(" password it naht 8 ki tu trong do co it nhat 1 ki tu dac biet, 1 ki tu in hoa, 1 ki tu thuong , 1 ki tu so"),
        body("avatarUrl").optional({
            checkFalsy: true
        }).isURL().withMessage("URL sai dinh dang"),
        body("role").optional().isMongoId().withMessage("role khong hop le"),
        body('images').optional().isArray({
            min: 1
        }).withMessage("hinh anh co it nhat 1"),
        body('images.*').isURL().withMessage("URL hinh anh phai hop le")
    ]
}