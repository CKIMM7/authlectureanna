const express = require('express');
const router = express.Router();

//const bcrypt = require('bcryptjs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const User = require('../models/user');

router.post('/register', async (req, res) => {
    try {
        const salt = await bcrypt.genSalt(12);
        const hashed = await bcrypt.hash(req.body.password, salt)
        await User.create({...req.body, password: hashed})
        res.status(201).json({msg: 'User created'})
    } catch (err) {
        res.status(500).json({err});
    }
})



router.post('/login', async (req, res) => {
    try {
        const user = await User.findByEmail(req.body.email)
        console.log(user);

        if(!user){ throw new Error('No user with this email') }
        const authed = bcrypt.compare(req.body.password, user.passwordDigest)
        if (!!authed){
            const payload = {
                user: user.username
            };

            const secret = "SUPERSECRETSTRING"; //load from .env file
            const options = {
                expiresIn: 60
            }

            const token = await jwt.sign(payload, secret, options)
            res.status(200).json({ token: token })
        } else {
            throw new Error('User could not be authenticated')  
        }
    } catch (err) {
        res.status(401).json({ err });
    }
})

module.exports = router
