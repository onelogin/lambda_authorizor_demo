require('dotenv').config({ silent: true });



 /*
 * Sample Lambda Authorizer to validate tokens originating from
 * OneLogin OIDC Provider and generate an IAM Policy
 */
const jwksClient = require('jwks-rsa');
const jwt = require('jsonwebtoken');
const util = require('util');

const apiPermissions = [
  {
    "arn": "arn:aws:execute-api:us-east-1:<AWSAccount>:3h7vfljsrj", // NOTE: Replace with your API Gateway API ARN
    "resource": "pets", // NOTE: Replace with your API Gateway Resource
    "stage": "dev", // NOTE: Replace with your API Gateway Stage
    "httpVerb": "GET",
    "scope": "openid"
  },
  {
    "arn": "arn:aws:execute-api:us-east-1:<AWSAccount>:3h7vfljsrj", // NOTE: Replace with your API Gateway API ARN
    "resource": "pets", // NOTE: Replace with your API Gateway Resource
    "stage": "dev", // NOTE: Replace with your API Gateway Stage
    "httpVerb": "OPTIONS",
    "scope": "email"
  },
  {
    "arn": "arn:aws:execute-api:us-east-1:<AWSAccount>:3h7vfljsrj", // NOTE: Replace with your API Gateway API ARN
    "resource": "pets", // NOTE: Replace with your API Gateway Resource
    "stage": "dev", // NOTE: Replace with your API Gateway Stage
    "httpVerb": "POST",
    "scope": "openid"
  },
  {
    "arn": "arn:aws:execute-api:us-east-1:<AWSAccount>:3h7vfljsrj", // NOTE: Replace with your API Gateway API ARN
    "resource": "pets/*", // NOTE: Replace with your API Gateway Resource
    "stage": "dev", // NOTE: Replace with your API Gateway Stage
    "httpVerb": "GET",
    "scope": "openid"
  },
  {
    "arn": "arn:aws:execute-api:us-east-1:<AWSAccount>:3h7vfljsrj", // NOTE: Replace with your API Gateway API ARN
    "resource": "pets/*", // NOTE: Replace with your API Gateway Resource
    "stage": "dev", // NOTE: Replace with your API Gateway Stage
    "httpVerb": "OPTIONS",
    "scope": "email"
  }
];

var generatePolicyStatement = function (apiName, apiStage, apiVerb, apiResource, action) {
  'use strict';
  // Generate an IAM policy statement
  var statement = {};
  statement.Action = 'execute-api:Invoke';
  statement.Effect = action;
  var methodArn = apiName + "/" + apiStage + "/" + apiVerb + "/" + apiResource;
  statement.Resource = methodArn;
  return statement;
};

var generatePolicy = function (principalId, policyStatements) {
  'use strict';
  // Generate a fully formed IAM policy
  var authResponse = {};
  authResponse.principalId = principalId;
  var policyDocument = {};
  policyDocument.Version = '2012-10-17';
  policyDocument.Statement = policyStatements;
  authResponse.policyDocument = policyDocument;
  return authResponse;
};

var verifyAccessToken = function (params) {
  'use strict';
    console.log(params);
    const token = getToken(params);

    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || !decoded.header || !decoded.header.kid) {
        throw new Error('invalid token');
    }

    const getSigningKey = util.promisify(client.getSigningKey);
    return getSigningKey(decoded.header.kid)
        .then((key) => {
            const signingKey = key.publicKey || key.rsaPublicKey;
            return jwt.verify(token, signingKey, jwtOptions);
        })
        .then((decoded));

};

const getToken = (params) => {
    if (!params.type || params.type !== 'TOKEN') {
        throw new Error('Expected "event.type" parameter to have value "TOKEN"');
    }

    const tokenString = params.authorizationToken;
    if (!tokenString) {
        throw new Error('Expected "event.authorizationToken" parameter to be set');
    }

    const match = tokenString.match(/^Bearer (.*)$/);
    if (!match || match.length < 2) {
        throw new Error(`Invalid Authorization token - ${tokenString} does not match "Bearer .*"`);
    }
    return match[1];
}

const client = jwksClient({
       cache: true,
       rateLimit: true,
       jwksRequestsPerMinute: 10, // Default value
       jwksUri: process.env.JWKS_URI
});

const jwtOptions = {
    audience: process.env.AUDIENCE,
    issuer: process.env.TOKEN_ISSUER
};

var generateIAMPolicy = function (user,scopeClaims) {
  'use strict';
  // Declare empty policy statements array
  var policyStatements = [];
  // Iterate over API Permissions
  for ( var i = 0; i < apiPermissions.length; i++ ) {
  // Check if token scopes exist in API Permission
  if ( scopeClaims.indexOf(apiPermissions[i].scope) > -1 ) {
  // User token has appropriate scope, add API permission to policy statements
  policyStatements.push(generatePolicyStatement(apiPermissions[i].arn, apiPermissions[i].stage, apiPermissions[i].httpVerb,
                                                apiPermissions[i].resource, "Allow"));
    }
  }
  // Check if no policy statements are generated, if so, create default deny all policy statement
  if (policyStatements.length === 0) {
    var policyStatement = generatePolicyStatement("*", "*", "*", "*", "Deny");
    policyStatements.push(policyStatement);
  }
  return generatePolicy(user, policyStatements);
};
exports.handler = async function(event, context) {
  // Declare Policy
  var iamPolicy = null;

  try {
    var data = await verifyAccessToken(event);
    var scopeClaims = data.scope;
    iamPolicy = generateIAMPolicy(data.sub, scopeClaims);
    console.log(JSON.stringify(iamPolicy));
  } catch(err) {
    console.log(err);
    var policyStatements = [];
    var policyStatement = generatePolicyStatement("*", "*", "*", "*", "Deny");
    policyStatements.push(policyStatement);
    iamPolicy = generatePolicy('user', policyStatements);


  }
  return iamPolicy;
};  



