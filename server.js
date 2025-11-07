const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const crypto = require('crypto');

function hashPassword(password) {
  return crypto.createHash('sha256')
               .update(password)
               .digest('hex');
}

const app = express();
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static('public'));

let xssEnabled = true;
let sdeEnabled = true;


const pool = new Pool({
  connectionString: process.env.DATABASE_URL, 
  ssl: {
    rejectUnauthorized: false   
  }
});

const createTables = async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS comments (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL,
      content TEXT NOT NULL
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users_sensitive (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL,
      password TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
};

createTables().then(() => console.log('Tables ensured')).catch(console.error);


app.get('/', (req, res) => {
  res.render('index');
});
app.get('/xss', async (req, res) => {
  const result = await pool.query('SELECT * FROM comments ORDER BY id DESC');
  res.render('xss', { comments: result.rows, vulnerable: xssEnabled });
});

app.post('/xss/toggle', (req, res) => {
  xssEnabled = req.body.xss === 'on';
  res.redirect('/xss');
});

app.post('/xss/comment', async (req, res) => {
  const { username, content } = req.body;
  await pool.query('INSERT INTO comments (username, content) VALUES ($1, $2)', [username, content]);
  res.redirect('/xss');
});
app.get('/sde', async (req, res) => {
  const result = await pool.query('SELECT * FROM users_sensitive ORDER BY id');
  res.render('sde', { users: result.rows, vulnerable: sdeEnabled });
});

app.post('/sde/toggle', (req, res) => {
  sdeEnabled = req.body.sde === 'on';
  res.redirect('/sde');
});

app.post('/sde/add', async (req, res) => {
  const { username, password } = req.body;

  if (sdeEnabled) {
    await pool.query(
      'INSERT INTO users_sensitive (username, password) VALUES ($1, $2)',
      [username, password]
    );
  } else {
    const hashedPassword = hashPassword(password);
    await pool.query(
      'INSERT INTO users_sensitive (username, password) VALUES ($1, $2)',
      [username, hashedPassword]
    );
  }

  res.redirect('/sde');
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
