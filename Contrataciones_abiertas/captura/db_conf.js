
var options = {};

pgp = require('pg-promise')(options);

const config = {
    host: process.env.POSTGRES_HOST || 'localhost',
    port: process.env.POSTGRES_PORT || 5432,
    database: process.env.POSTGRES_NAME ||'edca',
    user: process.env.POSTGRES_USER || 'tester',
    password: process.env.POSTGRES_PASSWORD || 'test'
};

var edca_db = pgp(config);

console.log('DB Config -> ', JSON.stringify(config));


module.exports = {
    edca_db : edca_db
};
