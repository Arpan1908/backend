const express = require('express');

const connect = require('./config/db')
const app = express();


const routes = require('./routes/route');
const helmet = require('helmet');
const morgan = require('morgan');
const cors = require('cors');





app.use(express.json());
connect();

app.use(express.json());
app.use(helmet());
app.use(cors()); 
app.use(morgan('combined')); 


app.use('/api/auth',routes)




app.listen(8000,()=>{
    console.log('Server started on port 8000');
})