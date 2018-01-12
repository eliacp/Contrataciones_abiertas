var mongoose = require('mongoose');

module.exports = mongoose.model('User',{
    name: String,
    lastname: String,
    username: String,
    password: String,
    email: String,
    address: String,
    isAdmin: Boolean
});
