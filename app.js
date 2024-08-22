const express = require("express")
const app = express()
const port = 4040
let bcrypt = require("bcrypt")
let session = require("express-session")
let con = require("./BaseDeDonnees")

let bodyParder = require("body-parser")
let { check, validationResult } = require("express-validator")
const { render } = require("ejs")

app.set("view engine","ejs")


app.use(express.static("public"))
app.use(bodyParder.json())
app.use(bodyParder.urlencoded({ extended:true }))

//=== Configuration de la session
app.use(session({
      secret: "simon08@#nodejs*********pierre",
      resave: false,
      saveUninitialized: false
}))

// ====== Route vers la page de connexion
app.get("/", (req,res)=>{
      res.render(__dirname+"/view/connexion",{errrorMessage:""})
})
// ====== Route vers la page d'inscription
app.get("/inscription", (req,res)=>{
      res.render(__dirname+"/view/inscription",{errrorMessage:""})
})
// ====== Route vers la page de mot de passe oublie
app.get("/mdp_oublie",(req,res)=>{
      res.render(__dirname+"/view/mdp_oublie",{errrorMessage:""})
})
//====== Route pour le mot de passe oublié
app.post("/mdp_oublie", (req,res)=>{
      let email = req.body.email

      
      if (!email){
            return res.render(__dirname+"/view/mdp_oublie",{errrorMessage:"Veuillez remplir ce champ"})
      }else{
            let sql = "SELECT * FROM utilisateur WHERE email=?"
            //===== Requête de sélection
            con.query(sql,[email],function(erreur,resultat){
                  if (erreur) console.log(erreur)

                  if (resultat.length > 0){
                        return res.render(__dirname+"/view/mdp_oublie",{errrorMessage:"Email trouvé"})
                  }else{
                        return res.render(__dirname+"/view/mdp_oublie",{errrorMessage:"Cet email n'existe pas !"})
                  }
            })
      }
      
})
//====== Route vers la page de mot de passe valide
app.get("/mdp_valide", (req,res)=>{
      res.render(__dirname+"/view/mdp_valide",{errrorMessage:""})
})
//====== Route pour la modification du mot de passe
app.post("/mdp_valide", (req,res)=>{
      let mdp1 = req.body.mdp1
      let mdp2 = req.body.mdp2

      if (!mdp1){
            res.render(__dirname+"/view/mdp_valide",{errrorMessage:"Saisir votre nouveau mot de passe"})
      }else if (!mdp2){
            res.render(__dirname+"/view/mdp_valide",{errrorMessage:"Confirmer le mot de passe"})
      }else if (mdp1 != mdp2){
            res.render(__dirname+"/view/mdp_valide",{errrorMessage:"Mots de passes non conformes"})
      }else{
            
      }
})
//********************* */
// ===== Route vers la page de modification
app.get("/modification",(req,res)=>{
      res.render(__dirname+"/view/modification")
})
app.get("/404",(req,res)=>{
      res.render(__dirname+"/view/404")
})
//====== Route vers la page d'affichage de données
app.get("/affichage",(req,res)=>{
      if (req.session.email){
            res.render(__dirname+"/view/affichage",{user:req.session.email})
      }else{
            res.redirect("/")
      }
})
//====== Route vers la page de message de succès
app.get("/msucces",(req,res)=>{
      res.render(__dirname+"/view/msucces")
})

//======  Route pour la création d'un compte
app.post("/inscription", (req,res)=>{
      const {nom,email,mdp} = req.body
      //========== Vérifier si les champs ne sont pas vides
      if (!nom){
            return res.render(__dirname+"/view/inscription",{errrorMessage:"Veuillez saisir votre nom"})
      }else if (!email){
            return res.render(__dirname+"/view/inscription",{errrorMessage:"Veuillez saisir votre email"})
      }else if (!mdp){
            return res.render(__dirname+"/view/inscription",{errrorMessage:"Veuillez saisir votre mot de passe"})
      }else if (mdp.length < 8){
            return res.render(__dirname+"/view/inscription",{errrorMessage:"Le mot de passe doit être au moins 8 caractères"})
      }else{
            //====== Cryptage du mot de passe
            const salt = bcrypt.genSaltSync(12)
            const hashedPassword = bcrypt.hashSync(mdp, salt)
            //====== Requête d'insertion
            let sql = "INSERT INTO utilisateur(nom,email,mdp) VALUES(?,?,?)"
            //====== Requete de selection
            con.query("SELECT email FROM utilisateur WHERE email=?",[email],function(error,result){
                  if (error) console.log(error)
                  //====== Vérifier si l'adresse mail saisie existe dans la base de données
                  if (result.length > 0){
                        return res.render(__dirname+"/view/inscription",{errrorMessage:"Cet email existe déjà !"})
                  }else{
                        con.query(sql,[nom,email,hashedPassword],function(error,result){
                              if (error) console.log(error)
                              res.redirect("/")
                        })
                  }
            })
      }
})
//====== Route vers la page de connexion
app.post("/",(req,res)=>{
      const {email,password} = req.body
      //===== Vérifier si les champs ne sont pas vides
      if (!email && !password){
            res.render(__dirname+"/view/connexion",{errrorMessage:"Veuillez remplir ces champs"})
      }else{
            //======= Requête de selection
            sql = "SELECT * FROM utilisateur WHERE email=?"
            con.query(sql,[email],function(error,result){
                  if (error) console.log(error)
                  //====== Vérifier si l'email saisi se trouve dans la base de données
                  if (result.length > 0){
                        //======= Comparaison du mot de passe
                        const hashedPassword = result[0].mdp
                        const matched = bcrypt.compareSync(password, hashedPassword);
                        //======= Vérifier les mots de passes sont conformes
                        if (matched){
                              req.session.isLoggedIn = true
                              req.session.email = email
                              res.redirect("/affichage")
                        }else{
                              res.render(__dirname+"/view/connexion",{errrorMessage:"Mot de passe incorrecte"})
                        }
                  }else{
                        res.render(__dirname+"/view/connexion",{errrorMessage:"Email incorrecte"})
                  }
            })
      }
})
//====== Vérifier si l'utilisateur
app.use((req, res, next) => {
      if (req.session.isLoggedIn) {
          next();
      } else {
          res.redirect('/');
      }
});
//====== Route pour la deconnexion d'un utilisateur
app.get("/logout", function(req,res){
      req.session.destroy(function(erreur){
            if (erreur){
                  console.log(erreur)
                  res.redirect("/")
            }
            res.redirect("/")
      })
})

//====== Route vers la page d'ajout de données
app.get("/ajout", (req,res)=>{
      if (req.session.email){
            res.render(__dirname+"/view/ajout",{errrorMessage:""})
      }else{
            res.redirect("/")
      }
})
//====== Route pour l'ajout d'une facture
app.post("/ajout", (req,res)=>{
      const {client,produit,quantite,prix,montant} = req.body
      //======= Vérifier si les champs sont vides
      if (!client){
            res.render(__dirname+"/view/ajout",{errrorMessage:"Entrez le nom du client"})
      }else if (!produit){
            res.render(__dirname+"/view/ajout",{errrorMessage:"Entrez le nom du produit"})
      }else if (!quantite){
            res.render(__dirname+"/view/ajout",{errrorMessage:"Entrez le quantité du produit"})
      }else if (!prix){
            res.render(__dirname+"/view/ajout",{errrorMessage:"Entrez le prix du produit"})
      }else if (!montant){
            res.render(__dirname+"/view/ajout",{errrorMessage:"Entrez le montant versé"})
      }else{
            let Tdate =  new Date()
            let Djour = Tdate.toLocaleDateString()
            let montantR = prix-montant
            let ref_utilisateur = req.session.email
            let sql = "INSERT INTO facturer(client,produit,quantite,prix,montantV,montantR,dateF,ref_utilisateur) VALUES(?,?,?,?,?,?,curdate(),?)"
            //====== Requête d'insertion de données
            con.query(sql,[client,produit,quantite,prix,montant,montantR,ref_utilisateur], function(error, result){
                  if (error) console.log(error)

                  res.redirect("/msucces")
            })
      }
})
//====== Route pour pour l'affichage des données
app.get("/contenu", (req,res)=>{
      let sql = "SELECT * FROM facturer WHERE ref_utilisateur=?"
      con.query(sql,[req.session.email], function(error,result){
            res.render(__dirname+"/view/contenut",{contenu:result})
      })  
})
//====== ROute pour afficher les donnéens dans la page enregistré
app.get("/rechercher", (req,res)=>{
      let sql = "SELECT * FROM facturer WHERE ref_utilisateur=?"
      con.query(sql,[req.session.email], function(error,result){
            res.render(__dirname+"/view/rechercher",{contenu:result})
      })  
})
//====== Route pour rechercher un facturer
app.get("/rechercher_fac",(req,res)=>{
      let element = req.query.element

      let sql = "SELECT * FROM facturer WHERE client LIKE ? AND ref_utilisateur = ?"
      con.query(sql,['%'+element+'%',req.session.email],function(error,result){
            if (error) console.log(error)

            res.render(__dirname+"/view/rechercher",{contenu:result})
      })
})
//====== Route pour la suppression d'une facture
app.get("/supprimer", (req,res)=>{
      let id = req.query.id
      let sql = "DELETE FROM facturer WHERE code=?"
      //====== Requête de suppression
      con.query(sql,[id],function(error,result){
            if (error) console.log(error)

            res.redirect("/affichage")
      })
})
//====== Route pour sélectionner un facture
app.get("/modifier", (req,res)=>{
      let id = req.query.id
      let sql = "SELECT * FROM facturer WHERE code=?"
      //======= Requête de sélection
      con.query(sql,[id],function(erreur,result){
            if (erreur) console.log(erreur)
            res.render(__dirname+"/view/modification",{resultat:result})
      })
})
//====== Route pour la mise à jour d'une facture
app.post("/modifier",(req,res)=>{
      let id = req.body.id
      let client = req.body.client
      let produit = req.body.produit
      let quantite = req.body.quantite
      let prix = req.body.prix
      let montantV = req.body.montantV
      let montantR = prix-montantV
      let dateF = req.body.dateF
      let sql = "UPDATE facturer SET client=?, produit=?, quantite=?, prix=?, montantV=?, montantR=?, dateF=? WHERE code=?"
      //======= Requête de mise à jour
      con.query(sql,[client,produit,quantite,prix,montantV,montantR,dateF,id],function(error, result){
            if (error) console.log(error)
            res.redirect("/affichage")
      })
})
//====== Route vers la page 404
app.use((req,res)=>{
      res.render(__dirname+"/view/404")
})
//====== Démarrage du serveur
app.listen(port, function(){
      console.log("Demarrage du serveur sur le port "+port+"...")
})

