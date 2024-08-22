const mysql = require("mysql")

let con = mysql.createConnection({
      host : "localhost",
      user : "root",
      password : "",
      database : "facture"
})

//====== Vérifier la connexion à la base de données
con.connect(function(erreur){
      if (erreur) console.log(erreur)
      console.log("Connexion à la base de données...")
})

module.exports = con