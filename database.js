const mysql = require('mysql2');

const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  database: 'ce_employ',
  password: ''
});

module.exports = pool.promise();
