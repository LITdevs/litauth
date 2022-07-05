let db = require('./db');
setTimeout(() => {
	db.sendMigration('email', 'username', 'id')
}, 2000)