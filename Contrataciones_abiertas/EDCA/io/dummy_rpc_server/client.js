
var PROTO_PATH = '../../models/proto/record1.proto';

var grpc = require('grpc');
var proto = grpc.load(PROTO_PATH).record1;

function main() {

 var client1  = new proto.SendRPC('localhost:50051',
     grpc.credentials.createInsecure());

    client1.addRecord({

    }, function (err, response) {
        console.log(response)
    })
}

main();
