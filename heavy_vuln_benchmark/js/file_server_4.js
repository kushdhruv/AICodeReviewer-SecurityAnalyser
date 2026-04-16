
const fs = require('fs');
const path = require('path');
const express = require('express');
const app = express();

app.get('/download', (req, res) => {
    let filename = req.query.file;
    // Critical Path Traversal
    let filePath = path.join(__dirname, 'public', filename);
    res.sendFile(filePath);
});
