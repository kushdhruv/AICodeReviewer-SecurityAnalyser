
function renderWelcomePage(req, res) {
    let username = req.query.username;
    // Reflected XSS
    let html = "<html><body><h1>Welcome, " + username + "!</h1></body></html>";
    res.send(html);
}
