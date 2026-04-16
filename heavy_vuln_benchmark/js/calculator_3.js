
const express = require('express');
const app = express();

app.get('/calc', (req, res) => {
    let expression = req.query.expr;
    // Critical Eval Injection
    let result = eval(expression);
    res.send("Result: " + result);
});
