require('dotenv').config();
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const querystring = require('querystring');

const app = express();
const PORT = process.env.PORT || 8000;
const SHOPIFY_API_KEY = process.env.SHOPIFY_API_KEY || '650f6226372a2fa22cee178fa0f73a1e';
const SHOPIFY_API_SECRET = process.env.SHOPIFY_API_SECRET || '2297a6fa1afd20ff6704c6c2c5219f76';
const SCOPES = process.env.SCOPES || 'read_products,write_products';
const FORWARDING_ADDRESS = process.env.FORWARDING_ADDRESS || "https://50xh1w66-8000.inc1.devtunnels.ms";

app.use(express.static('public'));

app.use(cookieParser());
app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // Use true if using HTTPS
}));

app.get('/', (req, res) => {
    if (req.session.accessToken) {
        return res.send("You're authenticated")
    }

    const shop = req.query.shop;

    if (shop) {
        const state = crypto.randomBytes(16).toString('hex');
        const redirectUri = `${FORWARDING_ADDRESS}/shopify/callback`;
        const installUrl = `https://${shop}/admin/oauth/authorize?client_id=${SHOPIFY_API_KEY}&scope=${SCOPES}&state=${state}&redirect_uri=${redirectUri}`;

        res.cookie('state', state, { httpOnly: true, secure: true, sameSite: 'Strict' });
        res.redirect(installUrl);
    } else {
        return res.status(400).send('Missing shop parameter. Please add ?shop=your-development-shop.myshopify.com to your request');
    }
});

app.get('/shopify/callback', async (req, res) => {
    const { shop, hmac, code, state } = req.query;  
    const stateCookie = req.cookies?.state;

    if (state !== stateCookie) {
        return res.status(403).send('Request origin cannot be verified');
    }

    if (shop && hmac && code) {
        const map = Object.assign({}, req.query);
        delete map['hmac'];
        const message = querystring.stringify(map);
        const providedHmac = Buffer.from(hmac, 'utf-8');
        const generatedHash = Buffer.from(
            crypto
                .createHmac('sha256', SHOPIFY_API_SECRET)
                .update(message)
                .digest('hex'),
            'utf-8'
        );

        let hashEquals = false;
        try {
            hashEquals = crypto.timingSafeEqual(generatedHash, providedHmac);
        } catch (e) {
            hashEquals = false;
        }

        if (!hashEquals) {
            return res.status(400).send('HMAC validation failed');
        }

        const accessTokenRequestUrl = `https://${shop}/admin/oauth/access_token`;
        const accessTokenPayload = {
            client_id: SHOPIFY_API_KEY,
            client_secret: SHOPIFY_API_SECRET,
            code,
        };

        try {
            const response = await axios.post(accessTokenRequestUrl, accessTokenPayload);
            const accessToken = response.data.access_token;
            req.session.accessToken = accessToken;
            req.session.shop = shop;
            res.redirect('/')
        } catch (error) {
            res.status(error.response.status).send(error.response.data);
        }
    } else {
        res.status(400).send('Required parameters missing');
    }
});

// Sample middleware
function isAuthenticated(req, res, next) {
    if (req.session.accessToken) {
        next();
    } else {
        res.status(401).send('Unauthorized');
    }
}

app.get('/protected', isAuthenticated, (req, res) => {
    res.send('You are authenticated!');
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
