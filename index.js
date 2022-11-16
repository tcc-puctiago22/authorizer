const { CognitoJwtVerifier } = require('aws-jwt-verify');


const mapGroupsToPaths = [
  {
    path: 'GET/plans',
    group: 'ADMIN'
  }, 
  {
    path: 'GET/proposal',
    group: 'USER'
  }
];
  
exports.handler = async function(event, context) {
  
  const requestPath = event.methodArn
  var  path =  requestPath.substring(requestPath.indexOf("staging")+8, requestPath.length);
  console.log(path)

  const existingPaths = mapGroupsToPaths.map((config) => config.path)
  if (!existingPaths.includes(path)) {
    console.log('Invalid path')
     return generateDeny ('me', event.methodArn)
  }

  const authHeader = event.authorizationToken
  if (!authHeader) {
    console.log('No auth header')
     return generateDeny ('me', event.methodArn)
  }
 
  const token = authHeader.split(' ')[1]
 
  const verifier = CognitoJwtVerifier.create({
    userPoolId: process.env.USERPOOL_ID,
    tokenUse: 'id', 
    clientId: process.env.CLIENT_ID,
  });

  let payload
  try {
    payload = await verifier.verify(token);
    console.log('Token is valid. Payload:', payload);
  } catch {
    console.log('Token not valid!');
    return generateDeny ('me', event.methodArn)
  }

  // header has a 'Bearer TOKEN' format
  const matchingPathConfig = mapGroupsToPaths.find(
    (config) => path === config.path
  )
  const userGroups = payload['cognito:groups']
  if (userGroups.includes(matchingPathConfig.group)) {
    return generateAllow('me', event.methodArn)
    
  }

  return generateDeny ('me', event.methodArn)
}


// Help function to generate an IAM policy
var generatePolicy = function(principalId, effect, resource) {
    // Required output:
    var authResponse = {};
    authResponse.principalId = principalId;
    if (effect && resource) {
        var policyDocument = {};
        policyDocument.Version = '2012-10-17'; // default version
        policyDocument.Statement = [];
        var statementOne = {};
        statementOne.Action = 'execute-api:Invoke'; // default action
        statementOne.Effect = effect;
        statementOne.Resource = resource;
        policyDocument.Statement[0] = statementOne;
        authResponse.policyDocument = policyDocument;
    }
    // Optional output with custom properties of the String, Number or Boolean type.
    authResponse.context = {
        "stringKey": "stringval",
        "numberKey": 123,
        "booleanKey": true
    };
    return authResponse;
}
     
var generateAllow = function(principalId, resource) {
    return generatePolicy(principalId, 'Allow', resource);
}
     
var generateDeny = function(principalId, resource) {
  throw Error("Unauthorized")
  //generatePolicy(principalId, 'Deny', resource);
}