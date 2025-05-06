require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { MongoClient } = require('mongodb');

const app = express();
const port = process.env.PORT || 8000;

const client = new MongoClient(process.env.MONGODB_HOST);
let db;

async function connectDB() {
    await client.connect();
    db = client.db(process.env.MONGODB_DATABASE);
    console.log('Connected to MongoDB');
}
connectDB().catch(console.error);

app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');

app.use(session({
    secret: process.env.NODE_SESSION_SECRET,
    store: MongoStore.create({
        client,
        dbName: process.env.MONGODB_DATABASE,
        collectionName: 'sessions',
        ttl: 60 * 60 
    }),
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 60 * 60 * 1000 } 
}));

app.get('/', (req, res) => {
    res.render('home', { user: req.session.user });
});

app.get('/signup', (req, res) => {
    res.render('signup', { error: null });
});

app.post('/signupSubmit', async (req, res) => {
    const schema = Joi.object({
        name: Joi.string().max(20).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
    });

    const { error } = schema.validate(req.body);
    if (error) {
        return res.render('signup', { error: error.details[0].message });
    }

    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        const userCollection = db.collection('users');
        const existingUser = await userCollection.findOne({ email });
        if (existingUser) {
            return res.render('signup', { error: 'Email already exists' });
        }

        await userCollection.insertOne({ name, email, password: hashedPassword });
        req.session.user = { name, email };
        res.redirect('/members');
    } catch (err) {
        res.render('signup', { error: 'Database error' });
    }
});

app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.post('/loginSubmit', async (req, res) => {
    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
    });

    const { error } = schema.validate(req.body);
    if (error) {
        return res.render('login', { error: error.details[0].message });
    }

    const { email, password } = req.body;

    try {
        const userCollection = db.collection('users');
        const user = await userCollection.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.render('login', { error: 'Invalid email or password' });
        }

        req.session.user = { name: user.name, email };
        res.redirect('/members');
    } catch (err) {
        res.render('login', { error: 'Database error' });
    }
});

app.get('/members', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/');
    }
    const images = ['image1.jpg', 'image2.jpg', 'image3.jpg'];
    const randomImage = images[Math.floor(Math.random() * images.length)];
    res.render('members', { user: req.session.user, image: randomImage });
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

app.use((req, res) => {
    res.status(404).render('404');
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});