let db = require('./db');
setTimeout(() => {
	db.sendMigrationToAll()
}, 2000)