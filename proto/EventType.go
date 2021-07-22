package proto



// server register event
const SERVER_REGISTER = 1;
// reply to server register request
const SERVER_REGISTER_REPLY = 2
// update next hop for server
const UPDATE_NEXT_HOP = 3
// register client request to controller
const CLIENT_REGISTER_CONTROLLERSIDE = 4
// register client request to server
const CLIENT_REGISTER_SERVERSIDE = 5
// confirmation for successfully registering client
const CLIENT_REGISTER_CONFIRMATION = 6
// add a new client
const ADD_NEWCLIENT = 7
// announce phase event
const ANNOUNCEMENT = 8
// synchronize reputation map among servers
const SYNC_REPMAP = 9
// message phase event
const MESSAGE = 10
// vote phase event
const VOTE = 11
// round end event
const ROUND_END = 12
// return vote status event
const VOTE_REPLY = 13
// return msg status event
const MSG_REPLY = 14
// broadcast h for Pedersen Commitment
const BCAST_PEDERSEN_H = 15
// challenge honesty for Fujisaki-Okamoto Commitment's configuration
const GN_HONESTY_CHALLENGE = 16
// answer for honesty challenge
const GN_HONESTY_ANSWER = 17
// update H for Pedersen Commitment
const UPDATE_PEDERSEN_H = 18

const BCAST_PEDERSEN_RDIFF = 19

const INIT_PEDERSEN_R = 20
// client posts a new bridge
const POST_BRIDGE = 21
// client requests multiple bridges
const REQUEST_BRIDGES = 22
// coordinator ask other servers to sign bridge assignments
const SIGN_ASSIGNMENTS = 23
// servers sends back signatures for assignments
const GOT_SIGNS = 24

const ANNOUNCEMENT_FINALIZE = 25