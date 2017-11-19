var mongoose = require('mongoose');

module.exports = mongoose.model('Release', {

    ocid : String,
    id : String,
    date : date,
    tag : [],
    initiationType : String,

    planning : {
        budget : {},
        rationale : String,
        documents : [{}]
    },
    tender : {
        id : String,
        title: String,
        description: String,
        status : String,
        items : [{}],
        minValue:{},
        value : {},
        procurementMethod : String,
        procurementMethodRationale : String,
        awardCriteria :String ,
        awardCriteriaDetails : String ,
        submissionMethod : String ,
        submissionMethodDetails : String,
        tenderPeriod :{},
        enquiryPeriod : {},
        hasEnquiries : bool,
        eligibilityCriteria : String ,
        awardPeriod : {},
        numberOfTenderers : integer,
        tenderers : [{}],
        procuringEntity : {},
        documents : [{}],
        milestones : [{}],
        amendment : {
            date : date,
            changes : [{}],
            rationale : String
        }

    },
    buyer : {},
    awards : [{

    }],
    contracts : [{

    }],
    language : String
});

module.exports = mongoose.model('ReleasePackage', {

});

module.exports = mongoose.model('Record', {

});


module.exports = mongoose.model('RecordPackage',{

});