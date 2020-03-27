const express = require('express');
const app = express();
const morgan = require('morgan');
const cors = require('cors');


//const { mongoose} = require('./database');

// Settings
app.set('port', process.env.PORT || 3000);
app.set('son spaces', 2);

// Middlewares
app.use(morgan('dev'));
app.use(cors({origin: 'http://localhost:4200'}, {origin: 'http://localhost:3001'}));
app.use(express.urlencoded({extended: false}));
app.use(express.json());

// Routes
app.use('/api/clientes',require('./routes/routes'));

// Starting the server
app.listen(app.get(`port`), ()=>{
    console.log(`Server on port ${3000}`);
});