require('dotenv').config();
const express = require('express');
const { paymentsAPI } = require('./paymentsAPI2');

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

app.post('/paymentsAPI', async (req, res) => {
    try {
        const result = await paymentsAPI(req.body);
        res.json(result);

    } catch (error) {
        console.error("Error processing payment:", error);
        res.status(500).send("Internal Server Error");
    }
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
