const express = require("express")
const app = express()
const bcrypt = require('bcrypt');
require('dotenv').config();
const jwt = require('jsonwebtoken');
const cors = require("cors")

// Include the databse connection
const db = require('./dbexport');

// Middleware to parse JSON bodies
app.use(express.json());

// Use CORS
app.use(cors())

const SECRET_KEY = 'fnbrmena';

// Generate JWT
const generateToken = (user) => {
    return jwt.sign({ id: user.id, email: user.email, superuser: true }, SECRET_KEY);
};

app.get('/users', async (req, res) => {
    try {
        const usersQuery = `
            SELECT 
                u.*,
                COALESCE(json_agg(b.*) FILTER (WHERE b.user_id IS NOT NULL), '[]') AS bookmarks,
                COALESCE(json_agg(r.*) FILTER (WHERE r.user_id IS NOT NULL), '[]') AS reminders,
                COALESCE(json_agg(s.*) FILTER (WHERE s.session_id IS NOT NULL), '[]') AS sessions
            FROM 
                Users u
            LEFT JOIN 
                Bookmarks b ON u.id = b.user_id
            LEFT JOIN 
                Reminders r ON u.id = r.user_id
            LEFT JOIN 
                Sessions s ON u.id = s.user_id
            GROUP BY 
                u.id;
        `;

        const users = await db.query(usersQuery);

        // Remove password from each user in the result
        const usersWithoutPassword = users.rows.map(user => {
            const { password, ...userWithoutPassword } = user;
            return userWithoutPassword;
        });

        res.status(200).json(usersWithoutPassword);

    } catch (err) {
        console.error('Error fetching users:', err.stack);
        res.status(500).json({ status: 500, error: 'Internal Server Error' });
    }
});

// Endpoint to handle user registration
app.post('/register', async (req, res) => {
    const { email, displayname, password } = req.body;

    try {
        // Check if all required fields are provided
        if (!email || !displayname || !password) {
            return res.status(400).json({ status: 400, error: 'Email, display name, and password are required.' });
        }

        // Check if the email is already in use
        const emailCheckQuery = 'SELECT * FROM Users WHERE email = $1';
        const emailCheckValues = [email.toLowerCase()];
        const emailCheckResult = await db.query(emailCheckQuery, emailCheckValues);

        if (emailCheckResult.rows.length > 0) {
            return res.status(409).json({ status: 409, error: 'Email is already in use.' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert the new user into the database
        const text = 'INSERT INTO Users (email, displayname, password, account_created_at) VALUES ($1, $2, $3, $4) RETURNING *';
        const values = [email.toLowerCase(), displayname, hashedPassword, new Date()];

        const result = await db.query(text, values);
        const newUser = result.rows[0];

        // Update the user's last login and login history
        const updateTokenQuery = `
            UPDATE Users
            SET login_history = array_append(login_history, NOW()), last_login = NOW()
            WHERE id = $1
            RETURNING *;
        `;
        const { rows: updatedUserRows } = await db.query(updateTokenQuery, [newUser.id]);
        const updatedUser = updatedUserRows[0];

        // Generate a new JWT token
        const token = generateToken(updatedUser);

        // Create a new session object
        const newSession = {
            jwt_token: token,
            created_at: new Date(),
            expires_at: new Date(Date.now() + 2 * 60 * 60 * 1000), // Session expires in 2 hours
        };

        // Insert the new session into the Sessions table
        const insertSessionQuery = `
            INSERT INTO Sessions (
                user_id, jwt_token, created_at, expires_at
            ) VALUES ($1, $2, $3, $4) RETURNING *;
        `;
        const sessionValues = [
            updatedUser.id, newSession.jwt_token, newSession.created_at, newSession.expires_at
        ];

        const { rows: sessionRows } = await db.query(insertSessionQuery, sessionValues);
        const activeSession = sessionRows[0];

        // Fetch bookmarks, reminders, and egs (empty initially for a new user)
        const bookmarksQuery = 'SELECT * FROM Bookmarks WHERE user_id = $1';
        const remindersQuery = 'SELECT * FROM Reminders WHERE user_id = $1';
        const userId = updatedUser.id;

        const [bookmarksResult, remindersResult] = await Promise.all([
            db.query(bookmarksQuery, [userId]),
            db.query(remindersQuery, [userId]),
        ]);

        const bookmarks = bookmarksResult.rows;
        const reminders = remindersResult.rows;

        // Prepare the response
        const response = {
            id: updatedUser.id,
            email: updatedUser.email,
            display_name: updatedUser.displayname,
            account_created_at: updatedUser.account_created_at,
            last_login: updatedUser.last_login,
            is_superuser: updatedUser.superuser,
            is_banned: updatedUser.banned,
            session: {
                session_id: activeSession.session_id,
                created_at: activeSession.created_at,
                expires_at: activeSession.expires_at,
                jwt_token: activeSession.jwt_token
            },
            login_history: updatedUser.login_history,
            bookmarks,
            reminders,
        };

        res.status(201).json(response);
    } catch (err) {
        console.error('Error registering user:', err.stack);
        res.status(500).json({ status: 500, error: 'Internal Server Error' });
    }
});

// Endpoint to handle user login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        if (!email || !password) {
            return res.status(400).json({ status: 400, error: 'Email and password are required.' });
        }

        // Query to find the user by email
        const userQuery = 'SELECT * FROM Users WHERE email = $1';
        const userValues = [email];

        const { rows: userRows } = await db.query(userQuery, userValues);

        if (userRows.length === 0) {
            return res.status(401).json({ status: 401, error: 'Invalid email or password.' });
        }

        const user = userRows[0];

        // Compare the provided password with the hashed password stored in the database
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ status: 401, error: 'Invalid email or password.' });
        }

        if (user.banned) {
            return res.status(403).json({ status: 403, error: 'This account has been banned.' });
        }

        // Generate a new JWT token
        const token = generateToken(user);

        // Create a new session object
        const newSession = {
            jwt_token: token,
            created_at: new Date(),
            expires_at: new Date(Date.now() + 2 * 60 * 60 * 1000), // Session expires in 2 hours
        };

        // Insert the new session into the Sessions table
        const insertSessionQuery = `
            INSERT INTO Sessions (
                user_id, jwt_token, created_at, expires_at
            ) VALUES ($1, $2, $3, $4) RETURNING *;
        `;

        const sessionValues = [
            user.id, newSession.jwt_token, newSession.created_at, newSession.expires_at
        ];

        const { rows: sessionRows } = await db.query(insertSessionQuery, sessionValues);
        const activeSession = sessionRows[0];

        // Update the user's last login and login history
        const updateTokenQuery = `
            UPDATE Users
            SET login_history = array_append(login_history, NOW()), last_login = NOW()
            WHERE id = $1
            RETURNING *;
        `;
        const { rows: updatedUserRows } = await db.query(updateTokenQuery, [user.id]);
        const updatedUser = updatedUserRows[0];

        // Fetch bookmarks, reminders, and egs (empty initially for a new user)
        const bookmarksQuery = 'SELECT * FROM Bookmarks WHERE user_id = $1';
        const remindersQuery = 'SELECT * FROM Reminders WHERE user_id = $1';
        const userId = updatedUser.id;

        const [bookmarksResult, remindersResult] = await Promise.all([
            db.query(bookmarksQuery, [userId]),
            db.query(remindersQuery, [userId]),
        ]);

        const bookmarks = bookmarksResult.rows;
        const reminders = remindersResult.rows;

        // Prepare the response
        const response = {
            id: updatedUser.id,
            email: updatedUser.email,
            display_name: updatedUser.displayname,
            account_created_at: updatedUser.account_created_at,
            last_login: updatedUser.last_login,
            is_superuser: updatedUser.superuser,
            is_banned: updatedUser.banned,
            session: {
                session_id: activeSession.session_id,
                created_at: activeSession.created_at,
                expires_at: activeSession.expires_at,
                jwt_token: activeSession.jwt_token
            },
            login_history: updatedUser.login_history,
            bookmarks,
            reminders,
        };

        // Remove the password from the response
        delete updatedUser.password;

        res.status(200).json(response);
    } catch (err) {
        console.error('Error during login:', err.stack);
        res.status(500).json({ status: 500, error: 'Internal Server Error.' });
    }
});

// Endpoint to handle user logout
app.patch('/logout', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1]; // Extract token from Authorization header

    try {
        if (!token) {
            return res.status(400).json({ status: 400, error: 'No token provided.' });
        }

        // Find the user associated with the token
        const userQuery = 'SELECT id FROM Users WHERE jwt_token = $1';
        const { rows: userRows } = await db.query(userQuery, [token]);

        if (userRows.length === 0) {
            return res.status(401).json({ status: 401, error: 'Invalid token.' });
        }

        const userId = userRows[0].id;

        // Remove the JWT token and set session_active to false
        const updateSessionQuery = `
            UPDATE Users
            SET jwt_token = NULL, session_active = FALSE
            WHERE id = $1
        `;
        await db.query(updateSessionQuery, [userId]);

        res.status(200).json({ status: 200, message: 'Successfully logged out.' });
    } catch (err) {
        console.error('Error during logout:', err.stack);
        res.status(500).json({ status: 500, error: 'Internal Server Error.' });
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