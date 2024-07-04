const express = require("express")
const app = express()
const bcrypt = require('bcrypt');
require('dotenv').config();
const jwt = require('jsonwebtoken');

// Include the databse connection
const db = require('./dbexport');

// Middleware to parse JSON bodies
app.use(express.json());

const SECRET_KEY = 'fnbrmena';
const TOKEN_EXPIRATION = '100d';

// Generate JWT
const generateToken = (user) => {
    return jwt.sign({ id: user.id, email: user.email, superuser: true }, SECRET_KEY, { expiresIn: TOKEN_EXPIRATION });
};

app.get('/users', async (req, res) => {
    try {
        const usersQuery = `
            SELECT 
                u.id,
                u.email,
                u.displayname,
                u.password,
                u.account_created_at,
                u.last_login,
                COALESCE(json_agg(b.*) FILTER (WHERE b.id IS NOT NULL), '[]') AS bookmarks,
                COALESCE(json_agg(r.*) FILTER (WHERE r.id IS NOT NULL), '[]') AS reminders
            FROM 
                Users u
            LEFT JOIN 
                Bookmarks b ON u.id = b.user_id
            LEFT JOIN 
                Reminders r ON u.id = r.user_id
            GROUP BY 
                u.id;
        `;

        const users = await db.query(usersQuery)
        res.status(200).json(users.rows)

    } catch (err) {
        console.error('Error registering user:', err.stack);
        res.status(500).json({ error: 'Internal Server Error' });
    }
})

app.post('/register', async (req, res) => {

    const { email, displayname, password } = req.body;

    try {
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert the new user into the database
        const text = 'INSERT INTO Users (email, displayname, password, account_created_at) VALUES ($1, $2, $3, $4) RETURNING *';
        const values = [email, displayname, hashedPassword, new Date()];

        const result = await db.query(text, values);

        // Respond with the new user's details (excluding the password)
        const newUser = result.rows[0];
        const token = generateToken(newUser);
        res.status(201).json({ user: newUser, token });

    } catch (err) {
        console.error('Error registering user:', err.stack);
        res.status(500).json({ error: 'Internal Server Error' });
    }

})

// Endpoint to handle user login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Query to find the user by email
        const userQuery = 'SELECT * FROM Users WHERE email = $1';
        const userValues = [email];

        const { rows: userRows } = await db.query(userQuery, userValues);

        if (userRows.length === 0) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const user = userRows[0];

        // Compare the provided password with the hashed password stored in the database
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Fetch bookmarks and reminders
        const bookmarksQuery = 'SELECT * FROM Bookmarks WHERE user_id = $1';
        const remindersQuery = 'SELECT * FROM Reminders WHERE user_id = $1';
        const userId = user.id;

        const [bookmarksResult, remindersResult] = await Promise.all([
            db.query(bookmarksQuery, [userId]),
            db.query(remindersQuery, [userId])
        ]);

        const bookmarks = bookmarksResult.rows;
        const reminders = remindersResult.rows;

        // Prepare the response
        const response = {
            ...user,
            bookmarks,
            reminders
        };

        // Remove the password from the response
        delete response.password;

        const token = generateToken(user);
        res.status(200).json({ user: response, token });
    } catch (err) {
        console.error('Error during login:', err.stack);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(403).json({ error: 'No token provided' });
    }

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to authenticate token' });
        }

        console.log(decoded)

        // Save the decoded info in the request for use in other routes
        req.userId = decoded.id;
        next();
    });
};

app.get('/protected', verifyToken, (req, res) => {
    res.status(200).json({ message: 'This is a protected route', userId: req.userId });
});


app.listen(process.env.SERVER_PORT, () => {
    console.log("Server is running on port", process.env.SERVER_PORT)
})