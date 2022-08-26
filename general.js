require('dotenv').config();
const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const jwt = require("jsonwebtoken")

// const generateSessionToken = require('./sessionToken');

const app = express();
app.use(express.json());


const HOST = process.env.HOST
const USER = process.env.USER
const PASSWORD = process.env.PASSWORD
const DATABASE = process.env.DATABASE
const DB_PORT = process.env.DB_PORT


const newConnection = mysql.createPool({
    connectionLimit: 100,
    host: HOST,
    user: USER,
    password: PASSWORD,
    database: DATABASE,
    port: DB_PORT,
});


newConnection.getConnection((error, connection) => {
    if (error) throw error;
    console.log("Database connected successfully: " + connection.threadId);
});

// app.get('/createdb', (req, res) => {
//     let sql = 'CREATE DATABASE newdb';
//     newConnection.query(sql, (error, result) => {
//         if (error) throw error;
//         console.log(result);
//         res.send('Database created...');
//     });
// });

// app.get('api/general/create_account', (req, res) => {

// })
let sessionTokens = []

function generateSessionToken (user) {
    const sessionToken = jwt.sign(user, process.env.SESSION_TOKEN_SECRET, {expiresIn: "15m"})

    sessionTokens.push(sessionToken)
    return sessionToken
}

const port = process.env.PORT;
app.listen(port, () => console.log(`Server has started on port ${port}...`));

// create new user account
app.post('/api/general/create_account', async (req, res) => {
    
    // store username and hashed password
    const userName  = req.body.name;
    const passwordHash = await bcrypt.hash(req.body.password, 10);

    newConnection.getConnection( async (error, connection) => {
        if (error) throw error;

        const dbSearch = "SELECT * FROM users WHERE userName = ?"
        const querySearch = mysql.format(dbSearch, [userName]);

        const dbInsert = "INSERT INTO users VALUES (0,?,?)"
        const insertQuery = mysql.format(dbInsert,[userName, passwordHash]);

        // search to see if user already exists
        await connection.query(querySearch, async (error, result) => {

            // display search results on console
            if (error) throw error;
            console.log("------> Search Results");
            console.log(result.length);

            if (result.length != 0) {
                connection.release()
                console.log("------> User already exists");
                res.sendStatus(409) 
            } 

            else {
                await connection.query (insertQuery, (error, result)=> {
                
                connection.release()
                
                if (error) throw error;
                console.log ("--------> Created new User")
                console.log(result.insertId)
                res.sendStatus(201)
                })
            }

        });

    });
}) ;

// login an existing user
app.post('/api/general/login', (req, res) => {
    const userName = req.body.name
    const password = req.body.password

    newConnection.getConnection( async (error, connection) => {
        if (error) throw error;

        const dbSearch = "SELECT * FROM users WHERE userName = ?"
        const querySearch = mysql.format(dbSearch, [userName]);

        await connection.query(querySearch, async (error, result) => {
            connection.release()

            if (error) throw error;

            // check if user exists
            if (result.length == 0) {
                console.log("-------> User does not exist")
                res.sendStatus(404)
            }
            // check if password entered is correct
            else {
                const passwordHash = result[0].password

                if (await bcrypt.compare(password, passwordHash)) {
                    console.log('--------> Login Successful')
                    console.log('-------> Generating Session Token')

                    const token = generateSessionToken({userName: userName})
                    console.log(token)
                    res.json({sessionToken: token})

                    // res.send(`${userName} is logged in`)
                }

                else {
                    console.log('---------> Password Incorrect')
                    res.send("Password incorrect")
                }
            }
        })
    
    })


})


//logout user(invalidate session key)
app.delete('/api/general/logout', (req, res) => {
    sessionTokens = sessionTokens.filter( (c) => c != req.body.token)

    newConnection.getConnection( async (error, connection) => {
        if (error) {
            res.send('No such session token')
        };
        
        console.log('--------> Logged Out!')
        res.send("Logged Out!")
    })
    

})

app.get('/api/general/getsessions', (req, res) => {
    res.json(sessionTokens)
}) 