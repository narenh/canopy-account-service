// Placeholder so the Coolify service can be set up before the account
// service itself lands. Answers every request with a short note.
const http = require('http');
const PORT = process.env.PORT || 3000;
http
  .createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end('Canopy accounts: coming soon.\n');
  })
  .listen(PORT, () => console.log(`canopy-account placeholder listening on port ${PORT}`));
