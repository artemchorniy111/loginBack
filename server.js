const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const User = require('./model/user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = 'jfkjkjklj23kljlk#@@@#fkjhfdkjhkjhwdnfkldjklj2lj49j3po40j30j';

const myPort = 9998;

mongoose.connect('mongodb://localhost:27017/login-app', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true
});

const app = express();

app.use('/', express.static(path.join(__dirname, 'static')))

app.use(bodyParser.json()); // - middleware

app.post('/api/change-password', async (req, res) => {
    const { token, newpassword: plainTextPassword } = req.body;

    if(!plainTextPassword || typeof plainTextPassword !== 'string'){
        return res.json({ status: 'error', error: 'Invalid password'});
    }
    if(plainTextPassword.length < 5){
        return res.json({ status: 'error', error: 'Password is too short, at least 6 characters'});
    }

    try{
        const user = jwt.verify(token, JWT_SECRET);
        const _id = user.id;

        const password = await bcrypt.hash(plainTextPassword, 10)
        await User.updateOne({ _id }, {
            $set: { password }
        })
        res.json({ status: 'ok' })
    } catch(error){
        res.json({ status: 'error', error: 'Invalid...'})
    }
})

app.post('/api/login', async (req, res) => {

    const {username, password} = req.body;

    const user = await User.findOne({ username }).lean();

    if(!user){
        return res.json({ status: 'error', error: 'Invalid username/password'})
    }

    if(await bcrypt.compare(password, user.password)){

        const token = jwt.sign({ 
            id: user._id, 
            username: user.username 
        }, JWT_SECRET );

        console.log(token)

        return res.json({ status: 'ok', data: token })
    }



    res.json({ status: 'error', error: 'Invalid username/password'});
})

app.post('/api/register', async (req, res) => {

    const { username, password: plainTextPassword } = req.body;

    if(!username || typeof username !== 'string'){
        return res.json({ status: 'error', error: 'Invalid username' });
    }
    if(!plainTextPassword || typeof plainTextPassword !== 'string'){
        return res.json({ status: 'error', error: 'Invalid password'});
    }
    if(plainTextPassword.length < 5){
        return res.json({ status: 'error', error: 'Password is too short, at least 6 characters'});
    }

    const password = await bcrypt.hash(plainTextPassword, 10);

    try{
        const response = await User.create({
            username,
            password
        });
        console.log('User created successfully', response);
    } catch(error){
        if(error.code === 11000){
            //duplicate  key
        
            return res.json({status: 'error', error: 'Username alredy in use'});
        }
        throw error
    }

    // console.log(await bcrypt.hash(password, 10));
    
    res.json({status: 'ok'})
})

app.listen(myPort, () => {
    console.log(`Server up at ${myPort}`);
})