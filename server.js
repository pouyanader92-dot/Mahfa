const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const BIN_ID = process.env.JSONBIN_BIN_ID;
const API_KEY = process.env.JSONBIN_API_KEY;
const DB_URL = `https://api.jsonbin.io/v3/b/${BIN_ID}`;

const defaultDb = {
    users: [
        {username:'zeynab', password:'admin123', displayName:'خانم زینب', points:0},
        {username:'yasinkiaei', password:'yasinkiaei123', displayName:'یاسین کیایی', points:0},
        {username:'amirmohammadgoli', password:'amirmohammadgoli123', displayName:'امیرمحمد گلی', points:0},
        {username:'rezakarimpoor', password:'rezakarimpoor123', displayName:'رضا کریم پور', points:0},
        {username:'parhamdavoodi', password:'parhamdavoodi123', displayName:'پرهام داوودی', points:0},
        {username:'radinnabipoor', password:'radinnabipoor123', displayName:'رادین نبی پور', points:0},
        {username:'mahdihabibi', password:'mahdihabibi123', displayName:'مهدی حبیبی', points:0},
        {username:'pouyanader', password:'pouyanader123', displayName:'پویا نادر', points:0},
        {username:'zahramahmoudian', password:'zahramahmoudian123', displayName:'زهرا محمودیان', points:0},
        {username:'fatemefazli', password:'fatemefazli123', displayName:'فاطمه فضلی', points:0},
        {username:'kianadaryabari', password:'kianadaryabari123', displayName:'کیانا دریاباری', points:0},
        {username:'taranomhosseinzadeh', password:'taranomhosseinzadeh123', displayName:'ترنم حسین زاده', points:0},
        {username:'talmaghasemi', password:'talmaghasemi123', displayName:'تلما قاسمی', points:0},
        {username:'paniyaabbaspoor', password:'paniyaabbaspoor123', displayName:'پانیا عباس پور', points:0},
        {username:'alimoosavi', password:'alimoosavi123', displayName:'علی موسوی', points:0},
        {username:'farsamramazanzadeh', password:'farsamramazanzadeh123', displayName:'فرسام رمضان زاده', points:0},
        {username:'kiankarimnasab', password:'kiankarimnasab123', displayName:'کیان کریم نسب', points:0},
        {username:'sobhanzahedian', password:'sobhanzahedian123', displayName:'سبحان زاهدیان', points:0},
        {username:'sorenaghasemi', password:'sorenaghasemi123', displayName:'سورنا قاسمی', points:0},
        {username:'zavoshghabadi', password:'zavoshghabadi123', displayName:'زاووش قبادی', points:0},
        {username:'mohammadahamashaykh', password:'mohammadahamashaykh123', displayName:'محمدطاها مشایخ', points:0},
        {username:'samighasemzadeh', password:'samighasemzadeh123', displayName:'سامی قاسم زاده', points:0},
        {username:'mohammadaminafsharpoor', password:'mohammadaminafsharpoor123', displayName:'محمدامین افشار پور', points:0},
        {username:'kasraahmadi', password:'kasraahmadi123', displayName:'کسری احمدی', points:0},
        {username:'amirrezaabbasgholizadeh', password:'amirrezaabbasgholizadeh123', displayName:'امیررضا عباس قلی زاده', points:0}
    ],
    messages: []
};

app.get('/api/db', async (req, res) => {
    try {
        const response = await fetch(DB_URL + '/latest', { headers: { 'X-Master-Key': API_KEY } });
        if (!response.ok) throw new Error('Fetch failed');
        const data = await response.json();
        res.json(data.record);
    } catch (err) {
        console.error('GET Error:', err.message);
        res.json(defaultDb); // اگر دیتابیس قطع بود، حداقل سایت کرانش نکنه
    }
});

app.post('/api/db', async (req, res) => {
    try {
        const response = await fetch(DB_URL, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json', 'X-Master-Key': API_KEY },
            body: JSON.stringify(req.body)
        });
        if (!response.ok) throw new Error('Save failed');
        res.json({ success: true });
    } catch (err) {
        console.error('POST Error:', err.message);
        res.status(500).json({ error: 'Failed to save database' });
    }
});

app.listen(PORT, () => console.log(`Server running on ${PORT}`));
