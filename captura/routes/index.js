var express = require('express');
var router = express.Router();
const uuid = require('uuid/v4');

var path  = require('path');

// PostgreSQL database
var db_conf = require('../db_conf');

//passport db
var dbConfig = require('../db.js');
var mongoose = require('mongoose');
mongoose.Promise = require('bluebird');
mongoose.connect(dbConfig.url, {useMongoClient: true});

// Configuring Passport
var passport = require('passport');
var expressSession = require('express-session');

router.use(expressSession({secret: 'mySecretKey', resave : false , saveUninitialized: false}));
router.use(passport.initialize());
router.use(passport.session());

// Using the flash middleware provided by connect-flash to store messages in session
// and displaying in templates
var flash = require('connect-flash');
router.use(flash());


// Initialize Passport
/* ******************* */
var LocalStrategy   = require('passport-local').Strategy;
var User = require('../models/user');
var bCrypt = require('bcrypt-nodejs');

passport.use('login', new LocalStrategy({
        passReqToCallback : true
    },
    function(req, username, password, done) {
        // check in mongo if a user with username exists or not

        User.findOne({ 'username' :  username },
            function(err, user) {

                // In case of any error, return using the done method
                if (err)
                    return done(err);
                // Username does not exist, log the error and redirect back
                if (!user){
                    console.log('User Not Found with username '+username);
                    return done(null, false, req.flash('message', 'Usuario no registrado'));
                }
                // User exists but wrong password, log the error
                if (!isValidPassword(user, password)){
                    console.log('Contraseña no válida');
                    return done(null, false, req.flash('message', 'Contraseña no válida')); // redirect back to login page
                }
                // User and password both match, return user from done method
                // which will be treated like success
                return done(null, user);
            }
        );

    }
));


var isValidPassword = function(user, password){
    return bCrypt.compareSync(password, user.password);
};

// No usamos este código
/*
passport.use('signup', new LocalStrategy({
        passReqToCallback : true // allows us to pass back the entire request to the callback
      },
      function(req, username, password, done) {

        findOrCreateUser = function(){
          // find a user in Mongo with provided username
          User.findOne({ 'username' :  username }, function(err, user) {
            // In case of any error, return using the done method
            if (err){
              console.log('Error in SignUp: '+err);
              return done(err);
            }
            // already exists
            if (user) {
              console.log('User already exists with username: '+username);
              return done(null, false, req.flash('message','User Already Exists'));
            } else {
              // if there is no user with that email
              // create the user
              var newUser = new User();

              // set the user's local credentials
              newUser.username = username;
              newUser.password = createHash(password);
              newUser.email = req.param('email');
              newUser.firstName = req.param('firstName');
              newUser.lastName = req.param('lastName');

              // save the user
              newUser.save(function(err) {
                if (err){
                  console.log('Error in Saving user: '+err);
                  throw err;
                }
                console.log('User Registration succesful');
                return done(null, newUser);
              });
            }
          });
        };
        // Delay the execution of findOrCreateUser and execute the method
        // in the next tick of the event loop
        process.nextTick(findOrCreateUser);
      })
  );
*/
// Generates hash using bCrypt
const createHash = (password) => bCrypt.hashSync(password, bCrypt.genSaltSync(10), null);

// Passport needs to be able to serialize and deserialize users to support persistent login sessions
passport.serializeUser(function(user, done) {
    console.log('serializing user: ');
    console.log(user);
    done(null, user._id);
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        //console.log('deserializing user:',user);
        done(err, user);
    });
});

var isAuthenticated = function (req, res, next) {
    // if user is authenticated in the session, call the next() to call the next request handler
    // Passport adds this method to request object. A middleware is allowed to add properties to
    // request and response objects
    if (req.isAuthenticated())
        return next();
    // if the user is not authenticated then redirect him to the login page
    res.redirect('/');
};

var isNotAuthenticated = function (req, res, next) {
    if (req.isUnauthenticated())
        return next();
    // if the user is authenticated then redirect him to the main page
    res.redirect('/main');
};

/* * * * * * * * * * * RUTAS * * * * * * * * * * * * * */

/* GET home page. */
router.get('/', isNotAuthenticated, function (req, res, next) {
    res.render('index', {title: 'Sistema de captura de datos de contrataciones abiertas en México', message: req.flash('message')});
});

router.get('/admin/new-user.html', isAuthenticated, function(req, res){
    res.render('modals/new_user');
});

router.get('/admin/users.html', isAuthenticated,  function (req, res) {
    //console.log(req.user);
    User.find({ _id :{ $ne: req.user._id }}).then(function (users) {
        res.render('modals/users', {users: users});
    });

});

/* Handle sign up */
router.post('/user', isAuthenticated, function (req, res) {

    if ( req.user.isAdmin === true ) {
        const username = req.body.username.trim();

        User.findOne({'username': username}, function (err, user) {
            // In case of any error, return using the done method
            if (err) {
                console.log('Error in SignUp: ' + err);
                return done(err);
            }
            // already exists
            if (user) {
                console.log(`User already exists with username: ${username}`);
                res.jsonp({
                    status: 'Error',
                    message: `El usuario ${username} ya existe en la base de datos`
                });
                //return done(null, false, req.flash('message','User Already Exists'));
            } else {
                // if there is no user with that email
                // create the user
                let newUser = new User();

                // set the user's local credentials
                newUser.username = username;
                newUser.password = createHash(req.body.password);
                newUser.email = req.body.email;
                newUser.address = req.body.address;
                newUser.fullname = req.body.fullname;
                newUser.isAdmin = req.body.isAdmin === "true" ;

                // save the user
                newUser.save(function (err) {
                    if (err) {
                        console.log('Error in Saving user: ' + err);
                        res.jsonp({
                            status: "Error",
                            message: `Error al guardar el usuario ${usuario}`
                        });
                    }

                    res.jsonp({
                        status: "Ok",
                        message: `Se ha creado el usuario ${username}`
                    });
                });
            }
        });
    }else {
        res.send("<p><b>No estás autorizado para crear usuarios</b></p>");
    }

});

/* Handle Login POST */
router.post('/login', passport.authenticate('login', {
    successRedirect: '/main',
    failureRedirect: '/',
    failureFlash : true
}));

/* Handle Logout */
router.get('/signout', function(req, res) {
    req.logout();
    res.redirect('/');
});


/* GET main page. */
router.get('/main', isAuthenticated, function(req, res, next) {
    res.render('main', { user: req.user, title: 'Sistema de captura de datos de contrataciones abiertas en México' });
});

/* admin page */
router.get('/admin', isAuthenticated, function (req, res) {
    res.render('admin', {title: "Panel de administración del sistema", user: req.user });
});

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * */
router.post("/user-profile/", isAuthenticated, function (req, res) {
    var id = req.body.id;
    User.findOne({ '_id' : id }).then(function (data) {
       res.render('modals/user-profile',{user: data});
    });
});

router.post("/change-password/", isAuthenticated, function (req, res) {
    var id = req.body.id;
    User.findOne({ '_id' : id }).then(function (data) {
        res.render('modals/update-password',{user: data});
    });
});

router.post('/update/user/',isAuthenticated, function (req, res) {
    var id = req.body.id;
    var email = req.body.email;
    var fullname = req.body.fullname;
    var address= req.body.address;

    User.findOne({ '_id' : id }).then(function (data) {
        data.fullname = fullname;
        data.email = email;
        data.address = address;
        data.save();
        res.json({
            status : "Ok",
            description: "Los datos han sido actualizados"
        });
    }).catch(function (data) {
        console.log(data);
        res.json({
            status: "Error",
            description: "Ha ocurrido un error"
        })
    });

});

router.post('/update/password',isAuthenticated,function (req, res ) {

    var user_id = req.body.user_id;
    var old_pass = req.body.old_pass;
    var new_pass = req.body.new_pass;
    var confirm_pass = req.body.confirm_pass;

    User.findOne({ '_id' : user_id }).then(function (user) {

        if ( !isValidPassword(user, old_pass)){
            res.json({
                status : "Error",
                description: "Contraseña incorrecta"
            })
        } else if ( isValidPassword(user, old_pass) && new_pass === confirm_pass ){

            user.password =  bCrypt.hashSync( new_pass, bCrypt.genSaltSync(10), null);
            user.save();

            res.json({
                status: "Ok",
                description: "Contraseña actualizada"
            });
        } else if ( isValidPassword(user, old_pass) && new_pass !== confirm_pass ){
            res.json({
                status : "Error",
                description: "La nueva contraseña no coincide"
            })
        }

    }).catch(function (error) {
        console.log(error);
        res.json({
            status : "Error",
            description: "Ha ocurrido un error al actualizar la contraseña"
        })
    })

});


/* GET main page with data */
router.get('/main/:contractingprocess_id', isAuthenticated, function (req,res) {

    var query;
    if (req.user.isAdmin){
        query = db_conf.edca_db.one('select id as contractingprocess_id from contractingprocess where id = $1', [
            req.params.contractingprocess_id
        ]);
    } else {
        query = db_conf.edca_db.one("select contractingprocess_id from user_contractingprocess where user_id = $1 and contractingprocess_id =$2", [
            req.user.id,
            req.params.contractingprocess_id
        ]);
    }

    query.then(function (contratacion) {

        db_conf.edca_db.task(function (t) {
            // this = t = transaction protocol context;
            // this.ctx = transaction config + state context;
            return t.batch([
                t.one("select * from ContractingProcess where id = $1",  [contratacion.contractingprocess_id]),
                t.one("select * from Planning where contractingprocess_id= $1", [contratacion.contractingprocess_id]),
                t.one("select * from budget where contractingprocess_id = $1", [contratacion.contractingprocess_id]),
                t.one("select * from Tender where contractingprocess_id = $1", [contratacion.contractingprocess_id]),
                t.one("select * from Award where contractingprocess_id = $1", [contratacion.contractingprocess_id]),
                t.one("select * from Contract where contractingprocess_id = $1", [contratacion.contractingprocess_id]),
                t.one("select * from Implementation where contractingprocess_id = $1", [contratacion.contractingprocess_id]),
                t.manyOrNone("select distinct currency, alphabetic_code from currency order by currency"),
                t.manyOrNone("select * from implementationstatus")
            ]);
        })
        // using .spread(function(user, event)) is best here, if supported;
            .then(function (data) {
                console.log("Contracting process -> ",data[0].id); //CP
                console.log("Planning ->",data[1].id); //planning
                console.log("Budget ->",data[2].id); //budget
                console.log("Tender ->",data[3].id); //Tender
                console.log("Award -> ",data[4].id); //Award
                console.log("Contract -> ",data[5].id); //Contract
                console.log("Implementation ->", data[6].id); //implementation

                res.render('main', {
                    user: req.user,
                    title: 'Sistema de captura de datos de contrataciones abiertas en México',
                    cp: data[0],
                    planning: data[1],
                    budget: data[2],
                    tender: data[3],
                    award: data[4],
                    contract: data[5],
                    implementation: data[6],
                    currencies : data[7],
                    implementation_status: data[8]
                });
            }).catch(function (error) {
            console.log("Error", error);

            res.render('main', {
                user: req.user,
                title: 'Sistema de captura de datos de contrataciones abiertas en México',
                error: 'Ha ocurrido un error al cargar el proceso de contratación'
            });
        });
    }).catch(function (error) {
        console.log("Error", error);

        res.render('main', {
            user: req.user,
            title: 'Sistema de captura de datos de contrataciones abiertas en México',
            error: 'Proceso de contratación no encontrado'
        });
    });

});

// NUEVO PROCESO DE CONTRATACIÓN
router.post('/new-process', isAuthenticated, function (req, res) {
    db_conf.edca_db.tx(function (t) {
        return t.one("insert into ContractingProcess (fecha_creacion, hora_creacion, ocid, stage ) values (current_date, current_time, concat('CONTRATACION_', current_date,'_', current_time), 4) returning id")
            .then(function (process) {

                return t.batch([
                    process = { id : process.id },
                    t.one("insert into Planning (ContractingProcess_id) values ($1) returning id as planning_id", process.id),
                    t.one("insert into Tender (ContractingProcess_id) values ($1) returning id as tender_id", [process.id]),
                    t.one("insert into Award (ContractingProcess_id) values ($1) returning id as award_id", [process.id]),
                    t.one("insert into Contract (ContractingProcess_id) values ($1) returning id as contract_id", [process.id]),
                    //t.one("insert into Buyer (ContractingProcess_id) values ($1) returning id as buyer_id",[process.id]),
                    t.one("insert into Publisher (ContractingProcess_id) values ($1) returning id as publisher_id", [process.id]),
                    t.one("insert into user_contractingprocess(user_id, contractingprocess_id) values ($1,$2) returning id", [req.user.id, process.id]),
                    t.one("insert into tags values (default, $1, true, false, false, false, false, false, false, false, false, false,false, false, false, false, false, false) returning id", [ process.id ]),
                    t.one("insert into links(contractingprocess_id) values ($1) returning id", [process.id])
                ]);

            }).then(function (info) {
                return t.batch([
                    //process, planning, tender, award, contract, buyer, publisher,
                    { contractingprocess : { id: info[0].id } },
                    { planning : { id: info[1].planning_id } },
                    { tender : { id: info[2].tender_id } },
                    { award: { id:info[3].award_id } },
                    { contract: { id:info[4].contract_id } },
                    //{ buyer : { id: info[5].buyer_id } },
                    { publisher: { id: info[6].publisher_id } },
                    t.one("insert into Budget (ContractingProcess_id, Planning_id) values ($1, $2 ) returning id as budget_id", [info[0].id, info[1].planning_id]),
                    //t.one("insert into ProcuringEntity (contractingprocess_id, tender_id) values ($1, $2) returning id as procuringentity_id",[info[0].id, info[2].tender_id]),
                    t.one("insert into Implementation (ContractingProcess_id, Contract_id ) values ($1, $2) returning id as implementation_id", [info[0].id, info[4].contract_id])
                ]);
            });

    }).then(function (data) {
        console.log(data);
        res.json( { url: `/main/${data[0].contractingprocess.id}` } );

    }).catch(function (error) {
        console.log("ERROR: ", error);
        res.json({"id": 0});
    });
});


function dateCol( date ) {
    return (date === '')?null:date;
}

function numericCol( number ){
    return (isNaN(number))?null:number;
}

function stringCol( str ){
    return ( str===''?null:str);
}

/* Update Planning -> Budget */
router.post('/update-planning', isAuthenticated, function (req, res) {

    db_conf.edca_db.tx(function (t) {
        var planning = this.one("update planning set rationale = $1 where ContractingProcess_id = $2 returning id", [req.body.rationale, req.body.contractingprocess_id]);
        var budget = this.one("update budget set budget_source = $2, budget_budgetid =$3, budget_description= $4, budget_amount=$5, budget_currency=$6, budget_project=$7, budget_projectid=$8, budget_uri=$9" +
            " where ContractingProcess_id=$1 returning id",
            [
                req.body.contractingprocess_id,
                req.body.budget_source,
                req.body.budget_budgetid,
                req.body.budget_description,
                numericCol(req.body.budget_amount),
                req.body.budget_currency,
                req.body.budget_project,
                req.body.budget_projectid,
                req.body.budget_uri
            ]);

        return this.batch([planning, budget]);

    }).then(function (data) {
        res.send('La etapa de planeación ha sido actualizada');
        console.log('Update planning: ',data);
    }).catch(function (error) {
        console.log("ERROR: ",error);
        res.send('Error');
    });

});


router.post('/uris',isAuthenticated, function(req, res){
    var id = Math.abs ( req.body.id );

    db_conf.edca_db.task(function(t){
        return this.batch([
            this.one("select * from contractingprocess where id = $1",[ id ]),
            this.one("select * from tags where contractingprocess_id =$1", [ id ])
        ]);
    }).then(function (data) {
        res.render('modals/uri', {
            contractingprocess : data[0],
            tags: data[1]
        });
    }).catch(function (error) {
        console.log(error);
        res.render("<p>Error</p>");
    })

});

let isChecked = (checkbox) => {
    if (typeof checkbox !== "undefined"){
        return checkbox === 'on'
    }
    return false;
};

router.post('/update-uris',isAuthenticated, function (req, res) {
    //console.log(req.body);


    db_conf.edca_db.tx(function (t) {
        return this.batch([
            this.one("update contractingprocess set uri =$1, publicationpolicy = $2, license = $3, destino=$4 where id = $5 returning id", [
                req.body.uri,
                req.body.publicationpolicy,
                req.body.license,
                req.body.destino,
                req.body.id
            ]),
            this.one("update tags set planning=$2, planningUpdate=$3, tender=$4, tenderAmendment=$5, tenderUpdate=$6, tenderCancellation=$7, award=$8, " +
                "awardUpdate=$9, awardCancellation=$10, contract=$11, contractUpdate=$12, contractAmendment=$13, implementation=$14, implementationUpdate=$15, " +
                "contractTermination=$16, compiled=$17 where contractingprocess_id=$1 returning id",[
                req.body.id,
                isChecked(req.body.planning),
                isChecked(req.body.planningUpdate),
                isChecked(req.body.tender),
                isChecked(req.body.tenderAmendment),
                isChecked(req.body.tenderUpdate),
                isChecked(req.body.tenderCancellation),
                isChecked(req.body.award),
                isChecked(req.body.awardUpdate),
                isChecked(req.body.awardCancellation),
                isChecked(req.body.contract),
                isChecked(req.body.contractUpdate),
                isChecked(req.body.contractAmendment),
                isChecked(req.body.implementation),
                isChecked(req.body.implementationUpdate),
                isChecked(req.body.contractTermination),
                isChecked(req.body.compiled)
            ])
        ]);
    }).then(function (data) {
        console.log('Update URIs: ', data);
        res.json({
            status: "Ok",
            description: "Los datos han sido actualizados",
        });
    }).catch(function (error) {
        console.log(error);
        res.json({
            status: "Error",
            description: "Ha ocurrido un error"
        });
    });
});

/* Update Tender*/

router.post('/update-tender',isAuthenticated, function (req, res) {
    db_conf.edca_db.one("update tender set tenderid =$2, title= $3, description=$4, status=$5, minvalue_amount=$6, minvalue_currency=$7, value_amount=$8, value_currency=$9, procurementmethod=$10," +
        "procurementmethod_rationale=$11, awardcriteria=$12, awardcriteria_details=$13, submissionmethod=$14, submissionmethod_details=$15," +
        "tenderperiod_startdate=$16, tenderperiod_enddate=$17, enquiryperiod_startdate=$18, enquiryperiod_enddate=$19 ,hasenquiries=$20, eligibilitycriteria=$21, awardperiod_startdate=$22," +
        "awardperiod_enddate=$23, numberoftenderers=$24, amendment_date=$25, amendment_rationale=$26" +
        " where ContractingProcess_id = $1 returning id", [
        req.body.contractingprocess_id,
        req.body.tenderid,
        req.body.title,
        req.body.description,
        stringCol(req.body.status),
        numericCol(req.body.minvalue_amount),
        req.body.minvalue_currency,
        numericCol(req.body.value_amount),
        req.body.value_currency,
        stringCol(req.body.procurementmethod),
        req.body.procurementmethod_rationale,
        req.body.awardcriteria,
        req.body.awardcriteria_details,
        req.body.submissionmethod,
        req.body.submissionmethod_details,
        dateCol(req.body.tenderperiod_startdate),
        dateCol(req.body.tenderperiod_enddate),
        dateCol(req.body.enquiryperiod_startdate),
        dateCol(req.body.enquiryperiod_enddate),
        (req.body.hasenquiries==="true")?true:false,
        req.body.eligibilitycriteria,
        dateCol(req.body.awardperiod_startdate),
        dateCol(req.body.awardperiod_enddate),
        numericCol(req.body.numberoftenderers),
        dateCol(req.body.amendment_date),
        req.body.amendment_rationale
    ]).then(
        function (data) {
            console.log("Update tender: ", data);
            res.send("La etapa de licitación ha sido actualizada");
        }).catch(function (error) {
        res.send("ERROR");
        console.log("ERROR: ",error);
    });
});


/* Update Award */
router.post('/update-award',isAuthenticated, function (req, res) {
    db_conf.edca_db.one("update award set awardid=$2, title= $3, description=$4, rationale=$5, status=$6,award_date=$7," +
        "value_amount=$8,value_currency=$9,contractperiod_startdate=$10," +
        "contractperiod_enddate=$11,amendment_date=$12,amendment_rationale=$13 " +
        " where ContractingProcess_id = $1 returning id",
        [
            req.body.contractingprocess_id,
            req.body.awardid,
            req.body.title,
            req.body.description,
            stringCol(req.body.rationale),
            stringCol(req.body.status),
            dateCol(req.body.award_date),
            numericCol(req.body.value_amount),
            req.body.value_currency,
            dateCol(req.body.contractperiod_startdate),
            dateCol(req.body.contractperiod_enddate),
            dateCol(req.body.amendment_date),
            req.body.amendment_rationale
        ]
    ).then(
        function (data) {
            console.log("Update award: ", data);
            res.send("La etapa de adjudicación ha sido actualizada");
        }).catch(function (error) {
        console.log("ERROR: ",error);
        res.send("ERROR");
    });
});

/* Update Contract */
router.post('/update-contract', isAuthenticated, function (req, res) {
    db_conf.edca_db.one("update contract set contractid=$2, awardid=$3, title=$4, description=$5, status=$6, period_startdate=$7, period_enddate=$8, value_amount=$9, value_currency=$10," +
        " datesigned=$11, amendment_date=$12, amendment_rationale=$13 " +
        " where ContractingProcess_id = $1 returning id", [
        req.body.contractingprocess_id,
        req.body.contractid,
        req.body.awardid,
        req.body.title,
        req.body.description,
        stringCol(req.body.status),
        dateCol(req.body.period_startdate),
        dateCol(req.body.period_enddate),
        numericCol(req.body.value_amount),
        req.body.value_currency,
        dateCol(req.body.datesigned),
        dateCol(req.body.amendment_date),
        req.body.amendment_rationale
    ]).then(
        function (data) {
            res.send('La etapa de contratación ha sido actualizada');
            console.log("Update contract id: ", data);
        }).catch(function (error) {
        res.send('ERROR');
        console.log("ERROR: ",error);
    });
});

// New document
router.post('/new-document', isAuthenticated, function(req,res){
    db_conf.edca_db.one('insert into $1~ (contractingprocess_id, document_type, documentid, title, description, url, date_published, date_modified, format, language) values ($2,$3,$4,$5,$6,$7,$8,$9,$10,$11) returning id',
        [
            req.body.table,
            req.body.ocid,
            req.body.document_type,
            "doc-"+uuid(),//req.body.documentid,
            req.body.title,
            req.body.description,
            req.body.url,
            dateCol(req.body.date_published),
            dateCol(req.body.date_modified),
            req.body.format,
            req.body.language
        ]).then(function (data) {
        res.json({
            status: 'Ok',
            description:"Se ha creado un nuevo documento"
        });
        console.log("new "+ req.body.table + ": ", data);

    }).catch(function (error) {
        res.json({
            status : "Error",
            description: "Ha ocurrido un error"
        });
        console.log("Error: ", error);
    });
});

router.post('/newdoc-fields', function (req,res) {

    db_conf.edca_db.task(function (t) {
        return this.batch([
            this.manyOrNone("select * from language"),
            this.manyOrNone("select * from documenttype order by title")
        ]);
    }).then(function (data) {
        res.render('modals/newdoc-fields',{localid: req.body.localid, table: req.body.table, languages: data[0], documenttypes: data[1] });
    }).catch(function (error) {
        console.log(error);
    });
});

router.post('/new-item',isAuthenticated,function (req,res) {
    db_conf.edca_db.one('insert into $1~ (contractingprocess_id, itemid, description, classification_scheme, classification_id, classification_description, classification_uri,' +
        ' quantity, unit_name, unit_value_amount, unit_value_currency) values ($2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) returning id',
        [
            req.body.table,
            req.body.localid,
            "item-"+uuid(),//req.body.itemid,
            req.body.description,
            req.body.classification_scheme,
            req.body.classification_id,
            req.body.classification_description,
            req.body.classification_uri,
            numericCol(req.body.quantity),
            req.body.unit_name,
            numericCol(req.body.unit_value_amount),
            req.body.unit_value_currency
        ]).then(function (data) {
        console.log("New item: ", data);
        res.json({
            status: 'Ok',
            description:'Datos registrados'
        });
    }).catch(function (error) {
        console.log('ERROR: ', error);
        res.json({
            status: 'Ok',
            description: 'Ha ocurrido un error al registrar el hito'
        });
    });
});

router.post('/newitem-fields', function (req,res) {
    db_conf.edca_db.manyOrNone("select distinct currency, alphabetic_code from currency order by currency").then(function (data) {
        res.render('modals/newitem-fields', {localid: req.body.localid, table: req.body.table, currencies: data});
    }).catch (function (error) {
        console.log(error);
    })
});

router.post('/new-milestone', isAuthenticated,function (req,res) {
    console.log(req.body);
    db_conf.edca_db.one('insert into $1~ (contractingprocess_id, milestoneid, title, description, duedate, date_modified, type, status) ' +
        'values ($2,$3,$4,$5,$6,$7,$8,$9) returning id',
        [
            req.body.table,
            req.body.localid,
            "milestone-"+uuid(),//req.body.milestoneid,
            req.body.title,
            req.body.description,
            dateCol(req.body.duedate),
            dateCol(req.body.date_modified),
            req.body.type,
            req.body.status
        ]).then(function (data) {
        console.log("New milestone: ", data);
        res.json({
            status: 'Ok',
            description: 'Se ha registrado un nuevo hito'
        });
    }).catch(function (error) {
        console.log('ERROR: ', error);
        res.json({
            status : "Error",
            description:'Ha ocurrido un error al registrar el hito'
        });
    });

});

router.post('/newmilestone-fields', function (req,res) {
    res.render('modals/newmilestone-fields', { localid: req.body.localid , table : req.body.table });
});

router.post('/new-transaction', isAuthenticated,function (req,res) {
    db_conf.edca_db.one('insert into implementationtransactions (contractingprocess_id, transactionid, source, ' +
        'implementation_date, value_amount, value_currency, payment_method, ' +
        'providerorganization_scheme,providerorganization_id,providerorganization_legalname,providerorganization_uri,' +
        'receiverorganization_scheme,receiverorganization_id,receiverorganization_legalname,receiverorganization_uri, uri) ' +
        'values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) returning id',[
        req.body.localid,
        "transaction-"+uuid(),//req.body.transactionid,
        req.body.source,
        dateCol(req.body.implementation_date),
        numericCol(req.body.value_amount),
        req.body.value_currency,
        req.body.payment_method,

        req.body.providerorganization_scheme,
        req.body.providerorganization_id,
        req.body.providerorganization_legalname,
        req.body.providerorganization_uri,

        req.body.receiverorganization_scheme,
        req.body.receiverorganization_id,
        req.body.receiverorganization_legalname,
        req.body.receiverorganization_uri,

        req.body.uri
    ]).then(function (data) {
        console.log('New transaction: ', data);
        res.json({
            status: 'Ok',
            description: 'Se ha creado una nueva transacción'
        });
    }).catch(function (error) {
        console.log('ERROR: ', error);
        res.json({
            status:'Error',
            description: 'Ha ocurrido un error al registrar la transacción'
        });
    });
});

router.post('/newtransaction-fields', function (req,res) {
    db_conf.edca_db.manyOrNone("select distinct currency, alphabetic_code from currency order by currency").then(function (data) {
        res.render('modals/newtransaction-fields', { localid: req.body.localid, currencies: data });
    }).catch(function (error) {
        console.log(error);
    });
});

// new amendment change
router.post('/new-amendment-change',isAuthenticated, function (req, res) {
    db_conf.edca_db.one('insert into $1~ (contractingprocess_id, property, former_value) values ($2,$3,$4) returning id',[
        req.body.table,
        req.body.localid,
        req.body.property,
        req.body.former_value
    ]).then(function (data) {
        res.json({
            status : 'Ok',
            description: 'El cambio ha sido registrado'
        });
        console.log('New amendment change: ',data);
    }).catch(function (error) {
        res.json({
            status : 'Error',
            description: 'Ha ocurrido un error al registrar el cambio'
        });
        console.log('ERROR',error );
    });
});

router.post('/newamendmentchange-fields', function (req,res) {
    res.render('modals/newamendmentchange-fields', { localid: req.body.localid, table : req.body.table });
});


// Update publisher
router.post('/update-publisher',isAuthenticated, function (req, res) {

    db_conf.edca_db.one("update publisher set name=$2, scheme=$3, uid=$4, uri=$5 where id = $1 returning id",
        [
            req.body.id,
            req.body.name,
            req.body.scheme,
            req.body.uid,
            req.body.uri
        ]
    ).then(function (data) {
        res.json({
            status : 'Ok',
            description : 'Los datos han sido actualizados'
        }); // envía la respuesta y presentala en un modal
        console.log("Update publisher", data);
    }).catch(function (error) {
        res.json({
            status: "Error",
            description: "Ha ocurrido un error"
        });
        console.log("ERROR: ",error);
    });
});

router.post('/publisher', function (req, res) {
    db_conf.edca_db.one("select * from publisher where contractingprocess_id=$1",[req.body.localid]).then(function (data) {
        res.render('modals/publisher',{data: data});
    }).catch(function (error) {
        console.log("ERROR: ", error);
    });
});

//update OCID
router.post('/update-ocid',isAuthenticated,function (req, res) {
    db_conf.edca_db.one("update contractingprocess set ocid = trim($1) where id=$2 returning id",[ req.body.ocid, req.body.localid ]).then(function (data) {
        res.send("Identificador de proceso actualizado");
        console.log("Update ocid:", data);
    }).catch(function (error) {
        console.log("ERROR: ", error);
        res.send('ERROR');
    });
});

//buscar por periodo
router.post('/search-process-by-date', function (req, res) {
    db_conf.edca_db.manyOrNone("select * from ContractingProcess where fecha_creacion >= $1 and fecha_creacion <= $2",[
        req.body.fecha_inicial,
        req.body.fecha_final
    ]
    ).then(function (data) {
        //console.log(data);
        res.render('modals/process-list',{ data: data});
    }).catch(function (error) {
        console.log("ERROR: ",error);
        res.send('ERROR');
    });
});

router.post('/search-process-by-ocid',function(req, res){
    db_conf.edca_db.manyOrNone("select * from ContractingProcess where ocid ilike '%$1#%' ",[ req.body.ocid ]).then(function (data) {
        res.render('modals/process-list',{ data : data});
    }).catch(function (error) {
        console.log(error);
        res.send('ERROR');
    });
});


router.post('/search/', function (req, res) {
    res.render('modals/search');
});

router.get('/manual', function (req, res) {
    res.render('modals/manual');
});


//get list of transactions
router.post('/transaction-list',function (req, res) {
    db_conf.edca_db.manyOrNone('select * from implementationtransactions where contractingprocess_id=$1',[
        req.body.ocid
    ]).then(function(data){
        console.log(data);
        res.render('modals/transaction-list', {table : req.body.table, data: data});
    }).catch(function(error){
        console.log('ERROR: ', error);
        res.send('ERROR');
    });

});

//get list of organizations
router.post('/organization-list',function (req, res) {
    db_conf.edca_db.manyOrNone('select * from $1~ where contractingprocess_id=$2',[
        req.body.table,
        req.body.ocid
    ]).then(function(data){
        console.log(data);
        res.render('modals/organization-list', {table: req.body.table, data: data});
    }).catch(function(error){
        console.log('ERROR: ', error);
        res.send('ERROR');
    });

});

//get list of items
router.post('/item-list',function (req, res) {
    db_conf.edca_db.manyOrNone('select * from $1~ where contractingprocess_id=$2',[
        req.body.table,
        req.body.ocid
    ]).then(function(data){
        console.log(data);
        res.render('modals/item-list', {table: req.body.table, data: data});
    }).catch(function(error){
        console.log('ERROR: ', error);
        res.send('ERROR');
    });
});

//get list of documents
router.post('/document-list',function (req, res) {
    db_conf.edca_db.manyOrNone('select * from $1~ where contractingprocess_id=$2',[
        req.body.table,
        req.body.ocid
    ]).then(function(data){
        console.log(data);
        res.render('modals/document-list', {data: data, table: req.body.table});
    }).catch(function(error){
        console.log('ERROR: ', error);
        res.send('ERROR');
    });
});

//get list of milestones
router.post('/milestone-list',function (req, res) {
    db_conf.edca_db.manyOrNone('select * from $1~ where contractingprocess_id=$2',[
        req.body.table,
        req.body.ocid
    ]).then(function(data){
        console.log(data);
        res.render('modals/milestone-list', {table: req.body.table, data: data});
    }).catch(function(error){
        console.log('ERROR: ', error);
        res.send('ERROR');
    });
});

//get list of amendment changes
router.post('/amendmentchange-list',function (req, res) {
    db_conf.edca_db.manyOrNone('select * from $1~ where contractingprocess_id=$2',[
        req.body.table,
        req.body.ocid
    ]).then(function(data){
        console.log(data);
        res.render('modals/amendmentchange-list', {table: req.body.table, data: data});
    }).catch(function(error){
        console.log('ERROR: ', error);
        res.send('ERROR');
    });
});

router.delete('/contractingprocess',isAuthenticated, function (req, res) {

    db_conf.edca_db.one('delete from contractingprocess cascade where id = $1 returning id, ocid',[req.body.id]).then(function (cp) {
        console.log('Successfully deleted contracting process -> ', JSON.stringify(cp));
        res.json({
            status: 'Ok',
            id: cp.id,
            ocid: cp.ocid
        })
    }).catch(function (error) {
        res.json({
            status: 'Error',
            error: error
        });
    });

});

router.post('/delete', isAuthenticated,function (req,res) {
    console.log(req.body.id);
    console.log(req.body.table);
    db_conf.edca_db.result('delete from $1~ where id = $2', [
        req.body.table,
        req.body.id
    ]).then(function (result) {
        res.json( {msg: "Registros eliminados: " +result.rowCount, status : 0});
    }).catch(function (error) {
        res.json({msg: 'ERROR', status: 1});
        console.log('ERROR',error);
    });
});


//Protocol buffers
//var ProtoBuf = require("protobufjs");

var ocds = require('../io/ocds');

router.get('/publish/:type/:localid/:outputname', function (req,res) {
    var localid = req.params.localid;
    var type = req.params.type;


    ocds.getOCDSJSON( Number(req.params.localid) , req.params.type, db_conf.edca_db ).then(function (data) {

        delete data.localid;

        // var builder = ProtoBuf.loadProtoFile("../models/proto/ocds.proto"),
        //   OCDS = builder.build("OCDS"),
        // ReleasePackage = OCDS.ReleasePackages.ReleasePackage;


        /*
        delete data.releases[0].planning;
        delete data.releases[0].tender;
        delete data.releases[0].buyer;
        delete data.releases[0].awards;
        delete data.releases[0].contracts;
*/

        //var rp = new ReleasePackage(data);
        //var buffer = rp.encode();
        //console.log(buffer);
        //socket
        //send buffer

        res.json(data);
    }).catch(function (error) {
        console.log(error);
        res.json ({
            message: `El proceso ${localid} no existe`
        });
    });

});

var multer = require('multer');
var upload = multer({ dest: path.join(__dirname, './uploads')});

//Converter Class
var Converter = require("csvtojson").Converter;

router.post('/upload-stage', isAuthenticated, upload.single('datafile'), function (req, res) {

    console.log("Uploaded file: ", req.file);
    var converter = new Converter({});
    require('fs').createReadStream(req.file.path).pipe(converter);

    converter.on("error",function(errMsg,errData){
        //do error handling here
        console.log('Error: ', errMsg);
        console.log('Data: ', errData);
    });

    //end_parsed will be emitted once parsing finished
    converter.on("end_parsed", function (jsonArray) {
        //console.log(jsonArray); //here is your result jsonarray

        if (req.body.stage === 'planning'){

            /*
            INVITACION_LICITACION
            DESCRIPCION_CONTRATO
            FUENTE_PRESUPUESTARIA -> budget source
            IDENTIFICADOR_PRESUPUESTO -> budget id
            DESCRIPCION_PRESUPUESTO -> budget description
            MONTO_ASIGNADO -> budget amount
            MONEDA -> budget currency
            PROYECTO_PRESUPUESTARIO, -> budget_project
            IDENTIFICADOR_PROYECTO_PRESUPUESTARIO, -> budget_projectid
            URI_PRESUPUESTO, -> budget uri
            FUNDAMENTO, -> planning -> rationale
            EVALUACION_NECESIDADES,
            PLAN_PROYECTO,PLAN_CONTRATACION,
            ESTUDIO_FACTIBILIDAD,
            ESTUDIO_MERCADO,
            URL_ESTUDIO_FACTIBILIDAD,
            URL_PLAN_CONTRATACION,
            URL_EVALUACION_NECESIDADES,
            URL_ESTUDIO_MERCADO
            */

            db_conf.edca_db.tx (function (t) {

                return t.one('update planning set rationale = $2 where contractingprocess_id = $1 returning id as planning_id',
                    [
                        req.body.localid,
                        jsonArray[0].FUNDAMENTO
                    ]).then(function (data) {
                    var budget = t.one('update budget set budget_source = $2, budget_budgetid = $3, budget_description = $4, budget_amount = $5, budget_currency = $6, budget_project = $7, budget_projectid = $8,' +
                        'budget_uri = $9 where contractingprocess_id = $1 returning id as budget_id',
                        [
                            req.body.localid,
                            jsonArray[0].FUENTE_PRESUPUESTARIA,
                            jsonArray[0].IDENTIFICADOR_PRESUPUESTO,
                            jsonArray[0].DESCRIPCION_PRESUPUESTO,
                            Number(jsonArray[0].MONTO_ASIGNADO),
                            jsonArray[0].MONEDA,
                            jsonArray[0].PROYECTO_PRESUPUESTARIO,
                            jsonArray[0].IDENTIFICADOR_PROYECTO_PRESUPUESTARIO,
                            jsonArray[0].URI_PRESUPUESTO

                        ]);

                    return t.batch([data , budget]);
                });


            }).then(function (data) {
                console.log('PLanning stage loaded: ', data);
                res.redirect(`/main/${req.body.localid}`);
            }).catch(function (error) {
                console.log('ERROR: ',error);
                res.redirect(`/main/${req.body.localid}`);
            });

        } else if (req.body.stage === 'tender'){
            /*
            INVITACION_LICITACION,
            IDENTIFICADOR_LICITACION, -> tenderid

            TITULO_LICITACION, -> title
            DESCRIPCION_LICITACION, -> description
            ESTATUS_LICITACION, -> status
            VALOR_MINIMO, -> minvalue_amount
            MONEDA_VALOR_MINIMO, -> minvalue_currency
            VALOR, -> value_amount
            MONEDA_VALOR, -> value_currency
            METODO_ADQUISICION, -> procurementmethod

            CARACTER_ADQUISICION,
            FORMA_PROCESO_ADQUISICION,

            JUSTIFICACION_METODO, -> procurementmethod_rationale
            CRITERIO_ADJUDICACION, -> awardcriteria
            DETALLES_CRITERIO_ADJUDICACION, -> awardcriteria_details
            METODO_RECEPCION, -> submissionmethod
            DETALLES_METODO_RECEPCION, -> submissionmethod_details

            PERIODO_RECEPCION_PROPUESTAS, -> tender period startdate
            FECHA_INICIO_ACLARACIONES, -> enquiry period startdate
            FECHA_CIERRE_ACLARACIONES, -> enquiry period enddate
            TUVO_ACLARACIONES, -> has enquiries

            TUVO_TESTIGO_SOCIAL,
            IDENTIFICADOR_TESTIGO_SOCIAL,
            NOMBRE_TESTIGO_SOCIAL,

            CRITERIOS_ELIGIBILIDAD, -> eligibility criteria
            PERIODO_ADJUDICACION, -> awardperiod_startdate
            NUMERO_PARTICIPANTES, -> numberoftenderers

            NUMERO_PARTICIPANTES_INHABILITADOS,
            ENTIDAD_CONTRATACION,
            AVISO_LICITACION,
            AVISO_AUDIENCIA_PUBLICA,
            DOCUMENTOS_LICITACION,
            CRITERIOS_ELEGIBILIDAD_PUBLICADO,
            ESPECIFICACIONES_TECNICAS,
            CRITERIOS_EVALUACION,
            ACLARACIONES,
            PRESELECCION_PARTICIPANTES,
            PARTICIPANTES,
            DECLARACION_INTERESES,
            INHABILITACIONES,
            URL_DETALLES_CRITERIO_ADJUDICACION,
            URL_AVISO_LICITACION,
            URL_AVISO_AUDIENCIA_PUBLICA,
            URL_DOCUMENTOS_LICITACION,
            URL_CRITERIOS_ELEGIBILIDAD,
            URL_ESPECIFICACIONES_TECNICAS,
            URL_CRITERIOS_EVALUACION,
            URL_ACLARACIONES,
            URL_PARTICIPANTES,
            URL_INHABILITACIONES
            */
            db_conf.edca_db.one('update tender set tenderid =$2, title = $3, description  = $4, status = $5,  minvalue_amount = $6, minvalue_currency= $7, value_amount = $8, value_currency = $9, ' +
                'procurementmethod = $10, procurementmethod_rationale= $11, awardcriteria = $12, awardcriteria_details = $13, submissionmethod = $14, submissionmethod_details = $15, ' +
                'tenderperiod_startdate = $16 , enquiryperiod_startdate = $17, enquiryperiod_enddate = $18, hasenquiries = $19, ' +
                'eligibilitycriteria = $20, awardperiod_startdate = $21, numberoftenderers = $22' +
                ' where contractingprocess_id = $1 returning id as tender_id',
                [
                    req.body.localid,
                    jsonArray[0].IDENTIFICADOR_LICITACION,
                    jsonArray[0].TITULO_LICITACION,
                    jsonArray[0].DESCRIPCION_LICITACION,
                    'active', //jsonArray[0].ESTATUS_LICITACION
                    Number(jsonArray[0].VALOR_MINIMO),
                    jsonArray[0].MONEDA_VALOR_MINIMO,
                    Number(jsonArray[0].VALOR),
                    jsonArray[0].MONEDA_VALOR,

                    jsonArray[0].METODO_ADQUISICION,
                    jsonArray[0].JUSTIFICACION_METODO,
                    jsonArray[0].CRITERIO_ADJUDICACION,
                    jsonArray[0].DETALLES_CRITERIO_ADJUDICACION,
                    jsonArray[0].METODO_RECEPCION,
                    jsonArray[0].DETALLES_METODO_RECEPCION,

                    jsonArray[0].PERIODO_RECEPCION_PROPUESTAS,
                    jsonArray[0].FECHA_INICIO_ACLARACIONES,
                    jsonArray[0].FECHA_CIERRE_ACLARACIONES,
                    (jsonArray[0].TUVO_ACLARACIONES==="true")?true:false,

                    jsonArray[0].CRITERIOS_ELEGIBILIDAD,
                    jsonArray[0].PERIODO_ADJUDICACION,
                    Number (jsonArray[0].NUMERO_PARTICIPANTES)
                ]).then(function (data) {
                console.log('Tender stage loaded: ', data);
                res.redirect('/main/'+ req.body.localid);
            }).catch(function (error) {
                console.log("ERROR: ", error);
                res.redirect('/main/'+ req.body.localid);
            });

        } else if (req.body.stage === 'award') {

            /*
            IDENTIFICADOR_LICITACION,
            IDENTIFICADOR_ADJUDICACION, -> award id
            TITULO_ADJUDICACION, -> title
            DESCRIPCION_ADJUDICACION, -> description
            ESTATUS_ADJUDICACION, -> status
            FECHA_ADJUDICACION, -> award_date
            VALOR_ADJUDICACION, -> value_amount
            MONEDA_ADJUDICACION, -> value_currency
            NUMERO_INCONFORMIDADES_RECIBIDAS,
            NUMERO_INCONFORMIDADES_PROCESDENTES,
            NUMERO_INCONFORMIDADES_RECHAZADAS
            */

            db_conf.edca_db.one('update award set awardid = $2, title = $3, description = $4, status = $5, award_date = $6, value_amount = $7, value_currency = $8 where contractingprocess_id = $1 returning id as award_id',
                [
                    req.body.localid,
                    jsonArray[0].IDENTIFICADOR_ADJUDICACION,
                    jsonArray[0].TITULO_ADJUDICACION,
                    jsonArray[0].DESCRIPCION_ADJUDICACION,
                    'active',//jsonArray[0].ESTATUS,
                    jsonArray[0].FECHA_ADJUDICACION,
                    Number(jsonArray[0].VALOR_ADJUDICACION),
                    jsonArray[0].MONEDA_ADJUDICACION

                ]).then(function (data) {
                console.log('Award stage loaded: ', data);
                res.redirect('/main/'+ req.body.localid);
            }).catch(function (error) {
                console.log("ERROR: ", error);
                res.redirect('/main/'+ req.body.localid);
            });

        } else if (req.body.stage === 'contract'){

            /*IDENTIFICADOR_ADJUDICACION, -> awardid
            IDENTIFICADOR_CONTRATO, -> contractid
            IDENTIFICADOR_ADJUDICACION_CONTRATO,
            TITULO_CONTRATO, -> title
            DESCRIPCION_CONTRATO, -> description
            ESTATUS_CONTRATO, -> status
            PERIODO_CONTRATO_INICIO,-> period_startdate
            PERIODO_CONTRATO_FINAL, -> period_enddate
            VALOR_CONTRATO, -> value_amount
            FECHA_FIRMA_CONTRATO, -> datesigned
            CONTRATO_FIRMADO,
            CLAUSULAS,
            CRONOGRAMA_CONTRATO,
            ANEXOS_CONTRATO,
            GARANTIAS_ANTICIPO,
            GARANTIAS_CUMPLIMIENTO,
            SUBCONTRATOS,
            URL_CONTRATO_FIRMADO,
            URL_CLAUSULAS,
            URL_ANEXOS_CONTRATO,
            URL_GARANTIAS_ANTICIPO,
            URL_GARANTIAS_CUMPLIMIENTO*/
            db_conf.edca_db.one('update contract set awardid =$2, contractid = $3 ,title = $4, description=$5, status = $6, period_startdate=$7, period_enddate=$8, value_amount=$9,' +
                ' datesigned=$10 where contractingprocess_id = $1 returning id as contract_id',
                [
                    req.body.localid,
                    jsonArray[0].IDENTIFICADOR_ADJUDICACION,
                    jsonArray[0].IDENTIFICADOR_CONTRATO,
                    jsonArray[0].TITULO_CONTRATO,
                    jsonArray[0].DESCRIPCION_CONTRATO,
                    'active',//jsonArray[0].ESTATUS,
                    jsonArray[0].PERIODO_CONTRATO_INICIO,
                    jsonArray[0].PERIODO_CONTRATO_FINAL,
                    Number(jsonArray[0].VALOR_CONTRATO),
                    jsonArray[0].FECHA_FIRMA_CONTRATO
                ]).then(function (data) {
                console.log('Award stage loaded: ', data);
                res.redirect('/main/'+ req.body.localid);
            }).catch(function (error) {
                console.log("ERROR: ", error);
                res.redirect('/main/'+ req.body.localid);
            });
        }

        require('fs').unlink(req.file.path);
    });
});

router.post('/uploadfile-fields', function (req,res) {
    res.render('modals/uploadfile-fields', { localid: req.body.localid, stage: req.body.stage });
});

router.post('/update-implementation', function (req,res) {

    db_conf.edca_db.one('update implementation set status=$1 where contractingprocess_id=$2 returning id',[
        req.body.status !== "None"?req.body.status:null,
        req.body.contractingprocess_id
    ]).then(function (data) {
        console.log(data);
        res.send("La etapa de implementación ha sido actualizada");
    }).catch(function (error) {
        console.log(error);
        res.send('Ocurrió un error al actualizar la etapa de implementación')
    })

});


/* *
 *  OCDS 1.1
 *  */

router.post('/1.1/add_party.html', (req, res) => {
    res.render('modals/add_party.ejs', { contractingprocess_id : req.body.contractingprocess_id });
});

router.post('/1.1/parties.html', function (req, res) {
   let contractingprocess_id = req.body.contractingprocess_id;
   db_conf.edca_db.manyOrNone("select * from parties where contractingprocess_id = $1", [contractingprocess_id]).then(function (parties) {
       res.render('modals/parties.ejs', { parties: parties });
   });
});

//get parties
router.get('/1.1/parties', function (req, res) {

    //all parties
    if ( !isNaN(req.query.contractingprocess_id) && isNaN(req.query.party_id) ) {
        db_conf.edca_db.one('select * from parties where contractingprocess_id = $1', [
            req.body.contractingprocess_id
        ]).then(function (parties) {
            //get party roles
            res.jsonp({
                status :'Ok',
                data: parties
            });
        }).catch(function (error) {
            console.log(error);
            res.status(400).jsonp({
                status: 'Error',
                error: error
            });
        });
    } else if(!isNaN(req.query.contractingprocess_id) && !isNaN(req.query.party_id)){
        db_conf.edca_db.one('select * from parties where contractingprocess_id = $1 and id = $2', [
            req.body.contractingprocess_id, req.body.party_id
        ]).then(function (party) {
            //get party roles
            res.jsonp({
                status :'Ok',
                data: party
            });
        }).catch(function (error) {
            console.log(error);
            res.status(400).jsonp({
                status: 'Error',
                error: error
            });
        });

    } else {
        //error
        res.status(400).jsonp({
            status: 'Error',
            message: 'Parámetros incorrectos'
        })
    }
});

// new party
router.put('/1.1/party/', function (req,res) {
    //falta verificar que la organización no exista

    db_conf.edca_db.one('insert into parties (contractingprocess_id, name, partyid, identifier_scheme, ' +
        ' identifier_id, identifier_legalname, identifier_uri, address_streetaddress, address_locality, ' +
        ' address_region, address_postalcode, address_countryname, contactpoint_name, contactpoint_email, ' +
        ' contactpoint_telephone, contactpoint_faxnumber, contactpoint_url) values' +
        ' ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) returning id', [
        req.body.contractingprocess_id,
        req.body.name,
        req.body.partyid,
        req.body.identifier_scheme,
        req.body.identifier_id,
        req.body.identifier_legalname,
        req.body.identifier_uri,
        req.body.address_streetaddress,
        req.body.address_locality,
        req.body.address_region,
        req.body.address_postalcode,
        req.body.address_countryname,
        req.body.contactpoint_name,
        req.body.contactpoint_email,
        req.body.contactpoint_telephone,
        req.body.contactpoint_faxnumber,
        req.body.contactpoint_url
    ]).then(function (party) {

        return db_conf.edca_db.one('insert into roles(id, contractingprocess_id, parties_id, ' +
            'buyer, procuringentity, supplier, tenderer, funder, enquirer,' +
            'payer, payee, reviewbody) values (default,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) returning id, parties_id',[
            req.body.contractingprocess_id,
            party.id,
            isChecked(req.body.buyer),
            isChecked(req.body.procuringEntity),
            isChecked(req.body.supplier),
            isChecked(req.body.tenderer),
            isChecked(req.body.funder),
            isChecked(req.body.enquirer),
            isChecked(req.body.payer),
            isChecked(req.body.payee),
            isChecked(req.body.reviewBody)
        ]);

    }).then(function(data) {

        res.jsonp({
            status: 'Ok',
            description: "Parte registrada",
            data : data
        });
    }).catch(function (error) {
        console.log(error);
        res.status(400).jsonp({
            status: 'Error',
            error: error
        });
    });

});

router.post('/1.1/edit_party.html', function (req, res){
    db_conf.edca_db.task(function (t) {
        return this.batch([
            this.one('select * from parties where id = $1',[req.body.parties_id ]),
            this.one('select * from roles where parties_id = $1', [req.body.parties_id ])
        ])
    }).then(function (data) {
        res.render('modals/edit_party',{data: data[0], roles: data[1]});
    }).catch(function (error) {
        console.log(error);
        res.send("<b>Error</b>");
    })

});

//update party
router.post('/1.1/party', function(req,res){

    db_conf.edca_db.tx(function (t) {
        return t.batch([
            this.one('update parties set name=$1, partyid=$2, identifier_scheme=$3,' +
                ' identifier_id=$4, identifier_legalname=$5, identifier_uri=$6, address_streetaddress=$7, address_locality=$8,' +
                ' address_region=$9, address_postalcode=$10, address_countryname=$11, contactpoint_name=$12, contactpoint_email=$13,' +
                ' contactpoint_telephone=$14, contactpoint_faxnumber=$15, contactpoint_url=$16 where id = $17 returning id',[
                req.body.name,
                req.body.partyid,
                req.body.identifier_scheme,
                req.body.identifier_id,
                req.body.identifier_legalname,
                req.body.identifier_uri,
                req.body.address_streetaddress,
                req.body.address_locality,
                req.body.address_region,
                req.body.address_postalcode,
                req.body.address_countryname,
                req.body.contactpoint_name,
                req.body.contactpoint_email,
                req.body.contactpoint_telephone,
                req.body.contactpoint_faxnumber,
                req.body.contactpoint_url,
                req.body.parties_id
            ]),
            this.one('update roles set buyer=$2, procuringentity=$3, supplier=$4, tenderer=$5, funder=$6,' +
                'enquirer=$7, payer=$8, payee=$9, reviewbody=$10 where parties_id = $1 returning id', [
                req.body.parties_id,
                isChecked(req.body.buyer),
                isChecked(req.body.procuringEntity),
                isChecked(req.body.supplier),
                isChecked(req.body.tenderer),
                isChecked(req.body.funder),
                isChecked(req.body.enquirer),
                isChecked(req.body.payer),
                isChecked(req.body.payee),
                isChecked(req.body.reviewBody)
            ])
        ]);
    }).then(function(data){
        res.jsonp({
            status: 'Ok',
            description: "Los datos han sido actualizados"
        });
    }).catch(function (error) {
        console.log(error);
        res.status(400).jsonp({
            status : 'Error',
            description: "Ocurrió un error al actualizar los datos",
            error: error
        });
    });
});

router.delete('/1.1/party', isAuthenticated, function(req, res) {
    db_conf.edca_db.one('delete from parties where id = $1 returning id', [req.body.parties_id]).then(function (party) {
        res.jsonp({
            status : 'Ok',
            description: "El registro ha sido eliminado"
        });
    }).catch(function (error) {
        console.log(error);
        res.status(400).jsonp({
            status: 'Error',
            description: "Ocurrió un error al borrar el registro"
        });
    })
});


//delete all parties per contracting process
router.delete('/1.1/parties', function (req, res) {

    db_conf.edca_db.manyOrNone('delete from parties where contractingprocess_id = $1 returning id ',[
        req.body.contractingprocess_id
    ]).then(function(deleted_parties){
        res.jsonp({
            status: 'Ok',
            parties: deleted_parties
        });
    }).catch(function (error) {
        console.log(error);
        res.status(400).jsonp({
            status: 'Error',
            error: error
        });
    });

});

//debe existir una restricción para que asignar no más de un party como buyer o procuringEntity

//get amenments
router.get('/1.1/:path/amendments', function (req, res) {
    var rel = '';
    switch ( req.params.path ){
        case 'tender':
            rel = 'TenderAmendments';
            break;
        case 'awards':
            rel = 'AwardsAmendments';
            break;
        case 'contracts':
            rel = 'ContractsAmendments';
            break;
        default:
            res.status(400).jsonp({
                status: 'Error',
                message: 'Parámetros incorrectos'
            });
    }


    db_conf.edca_db.manyOrNone('select * from ~$1 where award_id=$2, contractingprocess_id=$3',[
        rel,
        req.body.award_id,
        req.body.contractingprocess_id
    ]).then(function (amendments) {

    }).catch(function (error) {
        console.log(error);
        res.status(400).jsonp({
            status: 'Error',
            error: error
        })
    })
});

//new amendment
router.put('/1.1/:path/amendment', function(req, res){

    var rel = '';
    switch ( req.params.path ){
        case 'tender':
            rel = 'TenderAmendments';
            break;
        case 'awards':
            rel = 'AwardAmendments';
            break;
        case 'contracts':
            rel = 'ContractsAmendments';
            break;
        default:
            res.status(400).jsonp({
                status: 'Error',
                message: 'Parámetros incorrectos'
            });
    }

    db_conf.one('insert into ~$1(contractingprocess_id, contract_id, amendment_date, rationale, amendment_id, ' +
        'description, amendsReleaseID, releaseID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9) returning id',[
        rel,
        req.body.contractingprocess_id,
        req.body.contract_id,
        req.body.amendment_date,
        req.body.rationale,
        req.body.amendment_id,
        req.body.description,
        req.body.amendsReleaseID,
        req.body.releaseID
    ]).then(function(data){
        res.jsonp({
            status: 'Ok',
            data: data
        });
    }).catch(function (error) {
        res.status(400).jsonp({
            status: 'Error',
            error: error
        });
    });
});

//update amendment
router.post('/1.1/:path/amendment', function(req, res){
    var rel = '';
    switch ( req.params.path ){
        case 'tender':
            rel = 'TenderAmendments';
            break;
        case 'awards':
            rel = 'AwardAmendments';
            break;
        case 'contracts':
            rel = 'ContractsAmendments';
            break;
        default:
            res.status(400).jsonp({
                status: 'Error',
                message: 'Parámetros incorrectos'
            });
    }

    db_conf.one('update ~$1 set contractingprocess_id=$2, contract_id=$3, amendment_date=$4, rationale=$5, amendment_id=$6, ' +
        'description=$7, amendsReleaseID=$8, releaseID=$9 where id = $10 returning id',[
        rel,
        req.bod.id,
        req.body.contractingprocess_id,//?
        req.body.contract_id, //?
        req.body.amendment_date,
        req.body.rationale,
        req.body.amendment_id,
        req.body.description,
        req.body.amendsReleaseID,
        req.body.releaseID,
        req.body.id
    ]).then(function(data){
        res.jsonp({
            status: 'Ok',
            data: data
        });
    }).catch(function (error) {
        res.status(400).jsonp({
            status: 'Error',
            error: error
        });
    });
});

//delete amenment
router.delete('/1.1/:path/amendment', function(req, res){
    var rel = '';
    switch ( req.params.path ){
        case 'tender':
            rel = 'TenderAmendments';
            break;
        case 'awards':
            rel = 'AwardAmendments';
            break;
        case 'contracts':
            rel = 'ContractsAmendments';
            break;
        default:
            res.status(400).jsonp({
                status: 'Error',
                message: 'Parámetros incorrectos'
            });
    }

    db_conf.edca_db.one('delete from ~$1 where id = $2',[
        rel,
        req.body.amendment_id
    ]).then(function (data) {
        res.json({
            status: 'Ok',
            data: data
        })
    }).catch(function (error) {
        res.json({
            status: 'Error',
            error: error
        })
    });
});

//get changes
router.get('/1.1/:path/changes', function (req, res) {
    var rel = '';
    switch ( req.params.path ){
        case 'tender':
            rel = 'TenderAmendmentsChanges';
            break;
        case 'awards':
            rel = 'AwardAmendmentsChanges';
            break;
        case 'contracts':
            rel = 'ContractsAmendmentsChanges';
            break;
        default:
            res.status(400).jsonp({
                status: 'Error',
                message: 'Parámetros incorrectos'
            });
    }

    db_conf.edca_db.manyOrNone('select * from ~$1 where contractingprocess_id =$2', [
        rel,
        req.body.contractingprocess_id
    ]).then(function (changes) {
        res.jsonp({
            status: 'Ok',
            data: changes
        });
    }).catch(function (error) {
        console.log(error);
        res.status(400).jsonp({
            status: 'Error',
            error: error
        });
    });
});

//new change
router.put('/1.1/:path/change', function (req, res) {
    var rel = '';
    switch ( req.params.path ){
        case 'tender':
            rel = 'TenderAmendmentsChanges';
            break;
        case 'awards':
            rel = 'AwardAmendmentsChanges';
            break;
        case 'contracts':
            rel = 'ContractsAmendmentsChanges';
            break;
        default:
            res.status(400).jsonp({
                status: 'Error',
                message: 'Parámetros incorrectos'
            });
    }

    db_conf.edca_db.one('insert into ~$1(contractingprocess_id, property, former_value) values ($2, $3, $4) returning id', [
        rel,
        req.body.contractingprocess_id,
        //req.body.award_id,
        //req.body.awardsamendments_id,
        req.body.property,
        req.body.former_value
    ]).then(function (data) {
        res.jsonp({
            status: 'Ok',
            data: data
        });
    }).catch(function (error) {
        console.log(error);
        res.jsonp({
            status: 'Error',
            error: error
        });
    });

});

//edit change
router.post('/1.1/:path/change', (req, res) => {

    var rel = '';
    switch ( req.params.path ){
        case 'tender':
            rel = 'TenderAmendmentsChanges';
            break;
        case 'awards':
            rel = 'AwardAmendmentsChanges';
            break;
        case 'contracts':
            rel = 'ContractsAmendmentsChanges';
            break;
        default:
            res.status(400).jsonp({
                status: 'Error',
                message: 'Parámetros incorrectos'
            });
    }

    db_conf.edca_db.one('update ~$1 set contractingprocess_id=$2, property=$3, former_value=$4 where id=$5 returning id', [
        rel,
        req.body.contractingprocess_id,
        //req.body.award_id,
        //req.body.awardsamendments_id,
        req.body.property,
        req.body.former_value,
        req.body.change_id
    ]).then(function (data) {
        res.jsonp({
            status: 'Ok',
            data: data
        });
    }).catch(function (error) {
        console.log(error);
        res.jsonp({
            status: 'Error',
            error: error
        });
    });
});

//delete change
router.delete('/1.1/change', function (req, res) {
    var rel = '';
    switch ( req.params.path ){
        case 'tender':
            rel = 'TenderAmendmentsChanges';
            break;
        case 'awards':
            rel = 'AwardsAmendmentsChanges';
            break;
        case 'contracts':
            rel = 'ContractsAmendmentsChanges';
            break;
        default:
            res.jsonp({
                status: 'Error',
                message: 'Opción desconocida'
            });
    }

    db_conf.edca_db.one('delete from ~$1 where id=$2 returning id',[
        rel,
        req.body.change_id
    ]).then(function (data) {
        res.jsonp({
            status: 'Ok',
            data: data
        });
    }).catch(function (error) {
        console.log(error);
        res.status(400).jsonp({
            status: 'Error',
            error: error
        });
    });
});

//delete changes
router.delete('/1.1/:path/changes', function (req, res) {

    //:path -> Tender, Awards, Contracts
    var rel = '';
    switch ( req.params.path ){
        case 'tender':
            rel = 'TenderAmendmentsChanges';
            break;
        case 'awards':
            rel = 'AwardsAmendmentsChanges';
            break;
        case 'contracts':
            rel = 'ContractsAmendmentsChanges';
            break;
        default:
            res.jsonp({
                status: 'Error',
                message: 'Opción desconocida'
            });
    }

    db_conf.edca_db.manyOrNone('delete from ~$1 where contractingprocess_id=$2 returning id',[
        rel,
        req.body.contractingprocess_id
    ]).then(function (deleted_changes) {
        res.jsonp({
            status: 'Ok',
            data: deleted_changes
        });
    }).catch(function (error) {
        res.status(400).jsonp({
            status: 'Error',
            error: error
        });
    });

});

module.exports = router;