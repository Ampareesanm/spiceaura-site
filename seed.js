// Run this script once (node seed.js) to populate sample products
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./spiceaura.db');
const items = [
  {name:'Ceylon Cinnamon - 100g', description:'Premium Ceylon cinnamon', price:4.99, image:'', stock:50},
  {name:'Black Pepper - 100g', description:'Freshly ground black pepper', price:3.49, image:'', stock:80},
  {name:'Cardamom - 50g', description:'Green cardamom pods', price:5.99, image:'', stock:40},
];
db.serialize(()=>{
  items.forEach(i=>{
    db.run('INSERT INTO products (name, description, price, image, stock) VALUES (?,?,?,?,?)', [i.name,i.description,i.price,i.image,i.stock]);
  });
  console.log('Seed complete');
  db.close();
});