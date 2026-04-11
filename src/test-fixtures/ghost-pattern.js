const db = require('./db');
module.exports = {
  browse: {
    query(frame) {
      const filter = frame.options.filter;
      const q = "SELECT * FROM posts WHERE slug = '" + filter + "'";
      return db.query(q);
    }
  }
};
