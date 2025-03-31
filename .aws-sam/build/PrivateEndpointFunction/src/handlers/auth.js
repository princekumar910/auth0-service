import jwt from 'jsonwebtoken';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// Get __dirname equivalent in ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Correct path to secret.pem
const secretPath = path.join(__dirname, 'secret.pem');

// Read the public key
const publicKey = fs.readFileSync(secretPath, 'utf8');

const generatePolicy = (principalId, methodArn) => {
  const apiGatewayWildcard = methodArn.split('/', 2).join('/') + '/*';

  return {
    principalId,
    policyDocument: {
      Version: '2012-10-17',
      Statement: [
        {
          Action: 'execute-api:Invoke',
          Effect: 'Allow',
          Resource: apiGatewayWildcard,
        },
      ],
    },
  };
};

export async function handler(event, context) {
  if (!event.authorizationToken) {
    throw 'Unauthorized';
  }
  
  const token = event.authorizationToken.replace('Bearer ', '');


  try {
    const claims = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
    const policy = generatePolicy(claims.sub, event.methodArn);

    return {
      ...policy,
      context: claims
    };
  } catch (error) {
    console.error('JWT Verification Failed:', error.message);
    throw 'Unauthorized';
  }
};
