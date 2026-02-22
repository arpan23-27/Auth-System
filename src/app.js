require("dotenv").config();

const express = require("express")
const cookieParser = require("cookie-parser");


const connectDB = require("./utils/db");
const authRoutes = require("./routes/authRoutes");


const app = express();



//Connect database
connectDB();


//Middleware
app.use(express.json());
app.use(cookieParser());


app.use("/api/auth", authRoutes);



//Health Check route
app.get("/health", (req, res) =>{
    res.status(200).json({status:"OK"});
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () =>{
    console.log(`Server listening on the port ${PORT}`)
});
