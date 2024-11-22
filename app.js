const express = require('express');
const etag = require('etag');
const mongoose = require('mongoose');
const Todo = require('./models/todo');
const User = require('./models/user');
const authController = require('./controller/authcontroller');
const authJwt = require('./middlewares/authJwt');
const controller = require('./controller/authcontroller');
const rateLimitMiddleware = require('./middlewares/rateLimiter');
var bcrypt = require("bcryptjs");


const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
mongoose.connect('mongodb://localhost:27017/API')
  .then(() => console.log('Connexion à MongoDB réussie !'))
  .catch(() => console.log('Connexion à MongoDB échouée !'));

app.get('/api/todos',async (req,res)=>{
try{
    const todos = await Todo.find();
    const todoJson = JSON.stringify(todos);
    res.json(todos);
    }catch (err) {
    res.status(500).send('Erreur lors de la récupération des tâches');
    }   
});

app.post('/api/todos', [authJwt.verifyToken, authJwt.isExist, rateLimitMiddleware],async (req, res) => {
    try {
        const newTodo = new Todo({
        title: req.body.title,
        completed: req.body.completed || false
        });
    
        const savedTodo = await newTodo.save();
        res.status(201).json(savedTodo);
    } catch (err) {
        res.status(500).send('Erreur lors de la création de la tâche');
    }
});

app.get('/api/todos/:id',async (req, res) => {
    try {
        const todo = await Todo.findById(req.params.id);
        if (!todo) {
            return res.status(404).send('Tâche non trouvée');
        }
        const todoJson = JSON.stringify(todo);
        const hash = etag(todoJson);
        if (req.headers['if-none-match'] === hash) {
            return res.status(304).send(); // Pas de modifications, renvoyer 304 Not Modified
        }
        res.setHeader('ETag', hash);
        res.status(200).json(todo);
    }catch (err) {
        res.status(500).send('Erreur lors de la création de la tâche');
    }
    
});

app.put('/api/todos/:id',[authJwt.verifyToken, authJwt.isExist, rateLimitMiddleware], async (req, res) => {
    const todo = await Todo.findById(req.params.id);
    if (!todo) {
        return res.status(404).send('Tâche non trouvée');
    }
    const clientETag = req.headers['if-match'];
    const currentETag = etag(JSON.stringify(todo));
    console.log(clientETag);
    console.log(currentETag);
    if (clientETag !== currentETag) {
        return res.status(412).send('Precondition Failed: ETag mismatch'); // 412 Precondition Failed
    }
    todo.title = req.body.title || todo.title;
    todo.completed = req.body.completed || todo.completed;
    const updatedTodo = await todo.save();
    res.status(200).json(updatedTodo);
});


app.post('/api/users',[authJwt.verifyToken, rateLimitMiddleware], async (req, res) => {
    try{
        const newUser = new User({
            username: req.body.username,
            password:  bcrypt.hashSync(req.body.password, 8),
            name: req.body.name
        })
        const savedUser = await newUser.save();
        res.status(201).json(savedUser);
    } catch (err) {
        res.status(500).send('Erreur lors de la création de l\'utilisateur: ' + err);
    }
})

app.get('/api/users', async (req, res) => {
    try{
        const users = await User.find();
        const usersJson = JSON.stringify(users);
        res.json(users);
    } catch(err){
        res.status(500).send('Erreur lors de la récupération des utilisateurs: ' + err);
    }
})

app.get('/api/users/:id', async (req, res) => {
    try{
        const user = await User.findById(req.params.id);
        if (!user){
            return res.status(404).send('Utilisateur non trouvé');
        }
        const userJson = JSON.stringify(user);
        const hash = etag(userJson);
        if (req.headers['if-none-match'] === hash){
            return res.status(304).send();
        }
        res.setHeader('ETag', hash);
        res.status(200).json(user);
    } catch(err){
        res.status(500).send('Erreur lors de la récupération de l\'utilisateur: ' + err);
    }
})

app.put('/api/users/:id',[authJwt.verifyToken, authJwt.isExist, rateLimitMiddleware], async (req, res) => {
    const user = await User.findById(req.params.id);
    if (!user) {
        return res.status(404).send('Utilisateur non trouvée');
    }
    user.name = req.body.name || user.name;
    const updatedUser = await user.save();
    res.status(200).json(updatedUser);
});

app.post('/api/auth/signup', controller.signup);
app.post('/api/auth/signin', controller.signin);

module.exports = app;