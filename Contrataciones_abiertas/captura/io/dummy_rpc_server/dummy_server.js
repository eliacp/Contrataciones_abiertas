

var PROTO_PATH = '../../models/proto/record1.proto';

var grpc = require('grpc');
var hello_proto = grpc.load(PROTO_PATH).record1;

/**
 * Implements the addRecord RPC method.
 */

function addRecord(call, callback) {
    console.log ("Unary Server Call: ",call);

    console.log( "JSON string:",call.request.payload.toString('ascii'));
      
    callback(null, { ok : true });

}

/**
 * Starts an RPC server that receives requests for the SendRPC service at the
 * sample server port
 */
function main() {
    var server = new grpc.Server();
    server.addProtoService(hello_proto.SendRPC.service, {addRecord: addRecord});
    server.bind('0.0.0.0:50051', grpc.ServerCredentials.createInsecure());
    server.start();
}

main();
