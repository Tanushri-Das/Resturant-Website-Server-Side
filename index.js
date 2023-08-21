const express=require('express');
const app=express();
const cors=require('cors');
require('dotenv').config()
const port=process.env.PORT || 5000;
const { MongoClient, ServerApiVersion } = require('mongodb');

app.use(cors());
app.use(express.json());



const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.tdjlbxg.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();

    const menuCollection=client.db('ResturantWebsite').collection('menu');
    const reviewCollection=client.db('ResturantWebsite').collection('reviews');
    const cartCollection=client.db('ResturantWebsite').collection('carts');

    app.get('/menu',async(req,res)=>{
        const result=await menuCollection.find().toArray();
        res.send(result);
    })

    app.get('/reviews',async(req,res)=>{
        const result=await reviewCollection.find().toArray();
        res.send(result);
    })


    // cart collection
    
    app.post('/carts',async(req,res)=>{
      const item=req.body;
      console.log(item);
      const result=await cartCollection.insertOne(item);
      res.send(result);
    })





    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {

  }
}
run().catch(console.dir);


app.get('/',(req,res)=>{
    res.send('Resturant server side is running');
})
app.listen(port,()=>{
    console.log(`Resturant website server side running on port ${port}`)
})